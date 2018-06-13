/*
 * Copyright (c) 2002-2003, 2009-2011 Raphael Manfredi
 *
 *----------------------------------------------------------------------
 * This file is part of gtk-gnutella.
 *
 *  gtk-gnutella is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  gtk-gnutella is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with gtk-gnutella; if not, write to the Free Software
 *  Foundation, Inc.:
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Zone allocator.
 *
 * A zone is, in its simplest expression, a memory chunk where fix-sized
 * blocks are sliced, all free blocks being chained together via a link
 * written in the first bytes of the block. To allocate a block, the first
 * free block is removed from the list. Freeing is just as easy, since we
 * insert the block at the head of the free list.
 *
 * Zone chunks are linked together to make a bigger pool.  Each chunk is
 * called a "subzone".
 *
 * The advantages for allocating from a zone are:
 *   - very fast allocation time.
 *   - absence of block header overhead.
 *   - no risk of memory fragmentation.
 *
 * The disadvantages are:
 *   - need to allocate the zone before allocating items.
 *   - need to pass-in the zone descriptor each time.
 *   - programmer must be careful to return each block to its native zone.
 *
 * Moreover, periodic calls to the zone gc are needed to collect unused chunks
 * when peak allocations are infrequent or occur at random.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 * @date 2009-2011
 */

#include "common.h"

/*
 * Debugging options.
 */

/**
 * Turning ZALLOC_SAFETY_ASSERT triggers safety assertions at zalloc() and
 * zfree() time that make sure the block being handled belongs to the zone
 * in which it is tracked.
 *
 * This is much more costly that turning on ZONE_SAFE, but it does not cause
 * any additional overhead on the blocks being allocated.  The runtime penalty
 * comes from zbelongs().
 */
#if 0
#define ZALLOC_SAFETY_ASSERT	/**< Enables costly assertions */
#endif

/**
 * Turning ZONE_SAFE allows to tag each allocated block to detect duplicate
 * freeing of blocks and verify that we always return blocks to proper zones.
 *
 * There is very little performance impact, however this requires two extra
 * pointers per allocated block.
 */
#if 0
#define ZONE_SAFE
#endif

/**
 * Turning ZONE_FRAMES allows to tag each allocated and freed block with
 * the corresponding allocation and freeing stack frame.
 */
#if 0
#define ZONE_FRAMES
#endif

#include "zalloc.h"

#include "array_util.h"
#include "atomic.h"
#include "dump_options.h"
#include "entropy.h"
#include "eslist.h"
#include "evq.h"
#include "hashing.h"		/* For integer_hash() and friends */
#include "hashtable.h"
#include "leak.h"
#include "log.h"			/* For statistics logging */
#include "malloc.h"			/* For MALLOC_FRAMES */
#include "memusage.h"
#include "misc.h"			/* For short_filename() */
#include "once.h"
#include "pslist.h"
#include "sha1.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "str.h"
#include "stringify.h"
#include "thread.h"			/* For thread_small_id() */
#include "tm.h"
#include "unsigned.h"
#include "vmm.h"
#include "xmalloc.h"
#include "xsort.h"

#include "override.h"		/* Must be the last header included */

#define zalloc_debugging(lvl)	G_UNLIKELY(zalloc_debug > (lvl))

#ifdef ZALLOC_SAFETY_ASSERT
#define safety_assert(x)		g_assert(x)
#else
#define safety_assert(x)
#endif

/**
 * Extra allocated zones.
 */
struct subzone {
	struct subzone *sz_next;	/**< Next allocated zone chunk, NULL if last */
	char *sz_base;				/**< Base address of zone arena */
	size_t sz_size;				/**< Size of zone arena */
	time_t sz_ctime;			/**< Creation time */
};

/**
 * Subzone information for garbage collection.
 */
struct subzinfo {
	char *szi_base;				/**< Base zone arena address (convenience) */
	const char *szi_end;		/**< Pointer to first byte after arena */
	char **szi_free;			/**< Pointer to first free block in arena */
	struct subzone *szi_sz;		/**< The subzone for which we keep extra info */
	unsigned szi_free_cnt;		/**< Amount of free blocks in zone */
};

/**
 * Garbage collecting data structure.
 *
 * At the tail of structure there is a subzinfo array which
 * contains sorted "struct subzinfo" entries, sorted by arena base address.
 */
struct zone_gc {
	struct subzinfo *zg_subzinfo;	/**< Big chunk containing subzinfos */
	time_t zg_start;				/**< Time at which GC was started */
	unsigned zg_zone_freed;			/**< Total amount of zones freed by GC */
	unsigned zg_zone_defragmented;	/**< Total amount of zones defragmented */
	unsigned zg_zones;				/**< Amount of zones in zg_subzinfo[] */
	unsigned zg_free;				/**< First subzinfo with free blocks */
	uint32 zg_flags;				/**< GC flags */
};

/**
 * Zone GC flags
 */
#define ZGC_SCAN_ALL	(1 << 0)	/**< Scan all subzones at next run */

#ifdef ZALLOC_SAFETY_ASSERT
typedef struct zrange {
	const char *start;				/**< Arena start */
	const char *end;				/**< First byte beyond */
} zrange_t;
#endif	/* ZALLOC_SAFETY_ASSERT */

enum zone_magic {
	ZONE_MAGIC = 0x58fdc399
};

/**
 * @struct zone
 *
 * Zone structure.
 *
 * Subzone structures are used to linked together several allocation arenas
 * that are used to allocate objects for the zone.
 */
struct zone {				/* Zone descriptor */
	enum zone_magic zn_magic;
	spinlock_t lock;		/**< Thread-safe lock */
	struct subzone zn_arena;
	struct zone_gc *zn_gc;	/**< Optional: garbage collecting information */
	char **zn_free;			/**< Pointer to first free block */
#ifdef ZALLOC_SAFETY_ASSERT
	zrange_t *zn_rang;		/**< Sorted array of subzone ranges */
#endif
	memusage_t *zn_mem;		/**< Dynamic memory usage statistics */
	size_t zn_size;			/**< Size of blocks in zone */
	unsigned zn_refcnt;		/**< How many references to that zone? */
	unsigned zn_hint;		/**< Hint size, for next zone extension */
	unsigned zn_cnt;		/**< Amount of used blocks in zone */
	unsigned zn_blocks;		/**< Total amount of blocks in zone */
	unsigned zn_subzones;	/**< Amount of subzones */
	unsigned zn_oversized;	/**< For GC: amount of times we see oversizing */
	unsigned zn_stid;		/**< Small thread-ID for private zones */
	uint embedded:1;		/**< Zone descriptor is head of first arena */
	uint private:1;			/**< Is thread-private: no locking needed */
};

static inline void
zone_check(const struct zone *zn)
{
	g_assert(zn != NULL);
	g_assert(ZONE_MAGIC == zn->zn_magic);
}

static hash_table_t *zt;		/**< Keeps size (rounded up) -> zone */
static uint32 zalloc_debug;		/**< Debug level */
static bool zalloc_always_gc;	/**< Whether zones should stay in GC mode */
static bool addr_grows_upwards;	/**< Whether newer VM addresses increase */
static bool zalloc_closing;		/**< Whether zclose() was called */
static bool zalloc_memusage_ok;	/**< Whether we can enable memusage stats */

#ifdef MALLOC_FRAMES
static hash_table_t *zalloc_frames;	/**< Tracks allocation frame atoms */
#endif
#if defined(TRACK_ZALLOC) || defined(MALLOC_FRAMES)
static hash_table_t *not_leaking;
static hash_table_t *alloc_used_to_real;
static hash_table_t *alloc_real_to_used;
static spinlock_t zleak_lock = SPINLOCK_INIT;
#define ZLEAK_LOCK		spinlock(&zleak_lock)
#define ZLEAK_UNLOCK	spinunlock(&zleak_lock)
#endif
#ifdef TRACK_ZALLOC
static leak_set_t *z_leakset;
#endif

/*
 * Optional additional overhead at the beginning of each block:
 *
 *  +---------------------+ <---- OVH_ZONE_SAFE_OFFSET   ^
 *  | BLOCK_USED magic    | ZONE_SAFE                    | OVH_ZONE_SAFE_LEN
 *  | zone_t *zone        |                              v
 *  +---------------------+ <---- OVH_TRACK_OFFSET       ^
 *  | char *filename      | TRACK_ZALLOC                 | OVH_TRACK_LEN
 *  | int line            |                              v
 *  +---------------------+ <---- OVH_TIME_OFFSET        ^
 *  | time_t atime        | MALLOC_TIME                  v OVH_TIME_LEN
 *  +---------------------+ <---- OVH_FRAME_OFFSET       ^
 *  | struct frame *alloc | MALLOC_FRAMES                |
 *  |        or           |        or                    | OVH_FRAME_LEN
 *  | struct stackatom *a | ZONE_FRAMES                  v
 *  +---------------------+ <---- returned alocation pointer
 *  |      ........       | User data
 *  :      ........       :
 *
 * The total length of the leading overhead is OVH_LENGTH.
 * Individual offets are relative to the real block start.
 *
 * FIXME: will not work on 64-bit architectures if pointers cannot be aligned
 * on 32-bit boundaries.
 */

/*
 * Define ZONE_SAFE to allow detection of duplicate frees on a zone object
 * or freeing directed to the wrong zone.
 *
 * Don't leave that as the default because it adds an overhead to each allocated
 * block, which defeats one of the advantages of having a zone allocation in
 * the first place!
 */
#if (defined(DMALLOC) || defined(TRACK_ZALLOC)) || defined(MALLOC_FRAMES)
#ifndef ZONE_SAFE
#define ZONE_SAFE
#endif
#endif

#define OVH_ZONE_SAFE_OFFSET	0
#ifdef ZONE_SAFE
#define OVH_ZONE_SAFE_LEN		(2 * sizeof(char *))
#else
#define OVH_ZONE_SAFE_LEN		0
#endif

#define OVH_TRACK_OFFSET	(OVH_ZONE_SAFE_OFFSET + OVH_ZONE_SAFE_LEN)
#ifdef TRACK_ZALLOC
#undef zalloc				/* We want the real zalloc() routine here */
#define OVH_TRACK_LEN		(sizeof(char *) + sizeof(int))
#else
#define OVH_TRACK_LEN		0
#endif

#define OVH_TIME_OFFSET		(OVH_TRACK_OFFSET + OVH_TRACK_LEN)
#ifdef MALLOC_TIME
#define OVH_TIME_LEN		(sizeof(time_t))
#else
#define OVH_TIME_LEN		0
#endif

#if defined(MALLOC_FRAMES) && defined(ZONE_FRAMES)
#error "MALLOC_FRAMES and ZONE_FRAMES are mutually exclusive"
#endif

#define OVH_FRAME_OFFSET	(OVH_TIME_OFFSET + OVH_TIME_LEN)
#if defined(MALLOC_FRAMES)
#define OVH_FRAME_LEN		sizeof(struct frame *)
#define INVALID_FRAME_PTR	((struct frame *) 0xdeadbeef)
#elif defined(ZONE_FRAMES)
#define OVH_FRAME_LEN		sizeof(struct stackatom *)
#define INVALID_FRAME_PTR	((struct stackatom *) 0xdeadbeef)
#else
#define OVH_FRAME_LEN		0
#endif

#define OVH_LENGTH \
	(OVH_ZONE_SAFE_LEN + OVH_TRACK_LEN + OVH_TIME_LEN + OVH_FRAME_LEN)

#ifdef ZONE_SAFE
#define BLOCK_USED			((char *) 0xff12aa35)	/**< Tag for used blocks */
#endif

#define DEFAULT_HINT		8		/**< Default amount of blocks in a zone */
#define MAX_ZONE_SIZE		32768	/**< Maximum zone size */
#define WALLOC_GC_THRESH	4096	/**< Blocksize limit for always-GC mode */

/**
 * Internal statistics collected.
 *
 * The AU64() fields are atomically updated (without taking the stats lock).
 */
static struct zstats {
	uint64 allocations;				/**< Total amount of allocations */
	uint64 freeings;				/**< Total amount of freeings */
	uint64 freeings_list;			/**< Total amount of freeings via list */
	uint64 freeings_list_blocks;	/**< Amount of blocks freed via list */
	AU64(allocations_gc);			/**< Subset of allocations in GC mode */
	AU64(freeings_gc);				/**< Subset of freeings in GC mode */
	uint64 subzones_allocated;		/**< Total amount of subzone creations */
	uint64 subzones_allocated_pages;	/**< Total pages used by subzones */
	uint64 subzones_freed;			/**< Total amount of subzone freeings */
	uint64 subzones_freed_pages;	/**< Total pages freed in subzones */
	AU64(zmove_attempts);			/**< Total attempts to move blocks */
	AU64(zmove_attempts_gc);		/**< Subset of moves attempted in GC mode */
	AU64(zmove_1_block_in_subzone);	/**< Moving 1 single block in its subzone */
	AU64(zmove_successful_gc);		/**< Subset of successful moves */
	AU64(zmove_successful_smart);	/**< Subset of successful moves */
	AU64(zmove_successful_subzone);	/**< Subset of successful moves */
	AU64(zgc_zones_freed);			/**< Total amount of zones freed by GC */
	AU64(zgc_zones_defragmented);	/**< Total amount of zones defragmented */
	AU64(zgc_fragments_freed);		/**< Total fragment zones freed */
	AU64(zgc_free_quota_reached);	/**< Subzone freeing quota reached */
	AU64(zgc_last_zone_kept);		/**< First zone kept to avoid depletion */
	AU64(zgc_runs);					/**< Allowed zgc() runs */
	AU64(zgc_zone_scans);			/**< Calls to zgc_scan() */
	AU64(zgc_scan_freed);			/**< Zones freed during zgc_scan() */
	uint64 zgc_excess_zones_freed;	/**< Zones freed during zn_shrink() */
	uint64 zgc_shrinked;			/**< Amount of zn_shrink() calls */
	size_t user_memory;				/**< Current user memory allocated */
	size_t user_blocks;				/**< Current amount of user blocks */
	/* Counter to prevent digest from being the same twice in a row */
	AU64(zalloc_stats_digest);
} zstats;
static spinlock_t zstats_slk = SPINLOCK_INIT;

#define ZSTATS_LOCK			spinlock_hidden(&zstats_slk)
#define ZSTATS_UNLOCK		spinunlock_hidden(&zstats_slk)

#define ZSTATS_INCX(x)		AU64_INC(&zstats.x)

/**
 * @return (physical) block size for a given zone.
 */
size_t
zone_blocksize(const zone_t *zone)
{
	zone_check(zone);

	return zone->zn_size;
}

/**
 * @return (logical, user-level) block size for a given zone.
 */
size_t
zone_size(const zone_t *zone)
{
	zone_check(zone);

	return zone->zn_size - OVH_LENGTH;
}

/**
 * @return the block overhead size, in bytes (normally 0, unless debugging).
 */
size_t
zalloc_overhead(void)
{
	return OVH_LENGTH;
}

/**
 * Describe zone verbosely in case of critical events, for debugging clues.
 */
static void G_COLD
zdescribe(const zone_t *zone)
{
	s_rawinfo("%s%szone %p, %s, "
		"refcnt=%u, hint=%u, cnt=%u, blocks=%u, free=%p, subzones=%u%s%s",
		zone->embedded ? "embedded " : "", zone->private ? "private " : "",
		zone, zone->zn_gc != NULL ? "GC mode" : "no GC",
		zone->zn_refcnt, zone->zn_hint, zone->zn_cnt, zone->zn_blocks,
		zone->zn_free, zone->zn_subzones,
		zone->private ? "for " : "",
		zone->private ? thread_safe_id_name(zone->zn_stid) : "");
}

/* Under REMAP_ZALLOC, map zalloc() and zfree() to g_malloc() and g_free() */

#ifdef REMAP_ZALLOC
void *
zalloc(zone_t *zone)
{
	return g_malloc(zone->zn_size);
}

void
zfree(zone_t *zone, void *ptr)
{
	(void) zone;
	g_free(ptr);
}

void
zgc(bool overloaded)
{
	(void) overloaded;
}
#else	/* !REMAP_ZALLOC */

static char **zn_extend(zone_t *);
static void *zgc_zalloc(zone_t *);
static void zgc_zfree(zone_t *, void *);
static void zgc_allocate(zone_t *zone);
static void zgc_dispose(zone_t *);
static void *zgc_zmove(zone_t *, void *);

#ifdef ZALLOC_SAFETY_ASSERT
/**
 * Compare two ranges.
 */
static int
zrange_cmp(const void *a, const void *b)
{
	const zrange_t *ra = a, *rb = b;

	return ptr_cmp(ra->start, rb->start);
}

/**
 * Is key falling into range?
 */
static int
zrange_falls_in(const zrange_t *ra, const void *key)
{
	if (ptr_cmp(key, ra->start) >= 0 && ptr_cmp(key, ra->end) < 0)
		return 0;

	return ptr_cmp(ra->start, key);
}

/**
 * Initialize the sorted range array to speed up zbelongs().
 */
static void
zrange_init(zone_t *zn)
{
	const struct subzone *sz;
	unsigned i = 0;

	g_assert(NULL == zn->zn_rang);

	XMALLOC_ARRAY(zn->zn_rang, zn->zn_subzones);

	for (sz = &zn->zn_arena; sz; sz = sz->sz_next) {
		g_assert(i < zn->zn_subzones);
		zn->zn_rang[i].start = sz->sz_base;
		zn->zn_rang[i++].end = ptr_add_offset(sz->sz_base, sz->sz_size);
	}

	g_assert(i == zn->zn_subzones);

	xqsort(zn->zn_rang, zn->zn_subzones, sizeof zn->zn_rang[0], zrange_cmp);
}

/**
 * Validates the block address within a zone, to make sure it lies at an
 * exact multiple of the zone's block size within its subzone..
 */
static bool
zvalid(const zone_t *zone, const zrange_t *range, const void *blk)
{
	size_t boff = ptr_diff(blk, range->start);

	g_assert_log(0 == boff % zone->zn_size,
		"%zu-byte zone: %zuK subzone %p, block %p, offset %zu (off by %zu)",
		zone->zn_size, zone->zn_arena.sz_size / 1024, range->start, blk,
		boff, boff % zone->zn_size);

	return TRUE;
}

/**
 * Validates that a GC subzinfo has proper szi_free and szi_free_cnt.
 */
static bool
zgc_subzinfo_valid(const zone_t *zone, const struct subzinfo *szi)
{
	size_t n;
	char **p;

	g_assert((0 == szi->szi_free_cnt) == (NULL == szi->szi_free));

	n = szi->szi_free_cnt;
	p = szi->szi_free;

	g_assert(n <= zone->zn_hint);

	while (n-- != 0) {
		g_assert(ptr_cmp(p, szi->szi_base) >= 0 &&
			ptr_cmp(p, szi->szi_end) < 0);
		p = (char **) *p;
	}

	g_assert(NULL == p);

	return TRUE;
}

/**
 * Check that block address falls within the set of addresses belonging to
 * the zone.
 *
 * @param zone		the zone to which block should belong
 * @param blk		block address
 *
 * @return TRUE if address belongs to the zone
 *
 * @attention due to the naive alogorithm used here, the runtime penalty is
 * astonishing.  Almost 60% of the CPU time ends up being spent there!
 */
static bool G_HOT
zbelongs(const zone_t *zone, const void *blk)
{
	if G_UNLIKELY(NULL == zone->zn_rang)
		zrange_init(deconstify_pointer(zone));

#define GET_ITEM(i)	(&zone->zn_rang[i])
#define FOUND(i)	return zvalid(zone, &zone->zn_rang[i], blk)

	BINARY_SEARCH(const zrange_t *, blk, zone->zn_subzones,
		zrange_falls_in, GET_ITEM, FOUND);

	s_rawcrit("%s(): block %p (%zu user bytes) not belonging to %zu-byte zone %p",
		G_STRFUNC, blk, zone->zn_size - OVH_LENGTH, zone->zn_size, zone);
	zdescribe(zone);

	return FALSE;
}

static inline bool
zbelongs_uptr(const zone_t *zone, const void *p)
{
	return zbelongs(zone, const_ptr_add_offset(p, -OVH_LENGTH));
}

/**
 * Clear sorted range array each time there is a subzone update.
 *
 * Each time a subzone is added or removed from the zone, this routine
 * must be called to clear the obsoleted sorted array.
 */
static void
zrange_clear(const zone_t *zone)
{
	if (zone->zn_rang != NULL) {
		zone_t *zw = deconstify_pointer(zone);
		xfree(zw->zn_rang);
		zw->zn_rang = NULL;
	}
}
#else	/* !ZALLOC_SAFETY_ASSERT */

#define zrange_clear(z)

#endif	/* ZALLOC_SAFETY_ASSERT */

#if defined(ZONE_SAFE) && defined(ZONE_FRAMES)

#define ZFREE_FRAME		0x1			/* Trailing stackatom pointer marking */

static inline struct stackatom *
zframe_get_pointer(const struct stackatom *a)
{
	return ulong_to_pointer(pointer_to_ulong(a) & ~ZFREE_FRAME);
}

static inline bool
zframe_is_free_frame(const struct stackatom *a)
{
	return ZFREE_FRAME == (pointer_to_ulong(a) & ZFREE_FRAME);
}

static inline struct stackatom *
zframe_mark_pointer(const struct stackatom *a)
{
	return ulong_to_pointer(pointer_to_ulong(a) | ZFREE_FRAME);
}

/**
 * Dump stackframe held in the block.
 */
static void
zframe_dump(const void *ptr, const char *msg)
{
	struct stackatom const * const *p =
		const_ptr_add_offset(ptr, -OVH_LENGTH + OVH_FRAME_OFFSET);

	s_warning("ZALLOC %p %s; %s frame is:", ptr, msg,
		zframe_is_free_frame(*p) ? "free" : "alloc");

	if (INVALID_FRAME_PTR == *p) {
		s_warning("%s(): invalid frame pointer, cannot dump stack frame",
			G_STRFUNC);
	} else {
		const struct stackatom *a = zframe_get_pointer(*p);
		stacktrace_atom_decorate(stderr, a,
			STACKTRACE_F_ORIGIN | STACKTRACE_F_SOURCE);
	}
}
#else	/* !ZONE_SAFE || !ZONE_FRAMES */

#define zframe_dump(p, msg)

#endif	/* ZONE_SAFE && ZONE_FRAMES */

/**
 * Hash a zone structure on size and small thread ID.
 */
static unsigned
zone_hash(const void *key)
{
	const zone_t *z = key;
	uint32 h;

	h = integer_hash_fast(z->zn_size) + u16_hash(z->zn_stid) -
			z->private * GOLDEN_RATIO_32;

	return hashing_mix32(h);
}

/**
 * Compare two zone structures on size and small thread ID.
 */
static bool
zone_eq(const void *a, const void *b)
{
	const zone_t *za = a, *zb = b;

	return za->zn_size == zb->zn_size && za->zn_stid == zb->zn_stid &&
		za->private == zb->private;
}

/**
 * Should we always put the zone in GC mode?
 */
static inline ALWAYS_INLINE bool
zgc_always(const zone_t *zone)
{
	return zalloc_always_gc || zone->zn_size >= WALLOC_GC_THRESH;
}

/**
 * Return block, with possible start address adjustment due to tracking and
 * markup, as determined by compile options.
 */
static inline void *
zprepare(zone_t *zone, char **blk)
{
	(void) zone;
#ifdef ZONE_SAFE
	*blk++ = BLOCK_USED;
	*blk++ = (char *) zone;
#endif
#ifdef TRACK_ZALLOC
	blk = ptr_add_offset(blk, OVH_TRACK_LEN);
#endif
#ifdef MALLOC_TIME
	{
		time_t *t = (time_t *) blk;
		*t = tm_time();
	}
	blk = ptr_add_offset(blk, OVH_TIME_LEN);
#endif
#ifdef MALLOC_FRAMES
	{
		struct frame **p = (struct frame **) blk;
		struct stacktrace t;

		stacktrace_get_offset(&t, 1);	/* Remove ourselves from trace */
		*p = get_frame_atom(&zalloc_frames, &t);
	}
	blk = ptr_add_offset(blk, OVH_FRAME_LEN);
#endif
#ifdef ZONE_FRAMES
	{
		struct stackatom const **p = (struct stackatom const **) blk;
		struct stacktrace t;

		stacktrace_get_offset(&t, 1);	/* Remove ourselves from trace */
		*p = stacktrace_get_atom(&t);
		g_assert(!zframe_is_free_frame(*p));
	}
	blk = ptr_add_offset(blk, OVH_FRAME_LEN);
#endif
	return blk;
}

/**
 * Lock zone.
 *
 * All locking of public zones is done with normal spinlocks, which are
 * not hidden and therefore need to be accounted for in the thread.
 *
 * Although this increases the lock cost, it also provides a safer zalloc()
 * implementation and makes the routines taking these locks proper "suspension"
 * points.  In case there is a crash or a fork() call, this is an important
 * property that greatly outweighs the additional cost, which then becomes
 * a necessary cost and not just overhead.
 *
 * Don't inline to get proper lock location with SPINLOCK_DEBUG
 */
#define zlock(zone) G_STMT_START {		\
	if G_UNLIKELY(zone->private)		\
		spinlock_direct(&zone->lock);	\
	else								\
		spinlock(&zone->lock);			\
} G_STMT_END

/**
 * Try to lock zone.
 */
static bool
zlock_try(zone_t *zone)
{
	if G_UNLIKELY(zone->private) {
		if (thread_small_id() == zone->zn_stid) {
			spinlock_direct(&zone->lock);
			return TRUE;
		}
		return FALSE;
	} else {
		return spinlock_try(&zone->lock);
	}
}

/**
 * Unlock zone.
 */
static inline void ALWAYS_INLINE
zunlock(zone_t *zone)
{
	if G_UNLIKELY(zone->private)
		spinunlock_direct(&zone->lock);
	else
		spinunlock(&zone->lock);
}

/**
 * Allcate memory with fixed size blocks (zone allocation).
 *
 * @return a pointer to a block containing at least 'size' bytes of
 * memory.  It is a fatal error if memory cannot be allocated.
 */
void * G_HOT
zalloc(zone_t *zone)
{
	char **blk;		/**< Allocated block */

	/* NB: this routine must be as fast as possible. No assertions */

	ZSTATS_LOCK;
	zstats.allocations++;
	zstats.user_blocks++;
	zstats.user_memory += zone->zn_size;
	ZSTATS_UNLOCK;
	memusage_add_one(zone->zn_mem);

	/*
	 * Grab first available free block and update free list pointer. If we
	 * succeed in getting a block, we are done so return immediately.
	 */

	zlock(zone);

	blk = zone->zn_free;
	if G_LIKELY(blk != NULL) {
		zone->zn_free = (char **) *blk;
		zone->zn_cnt++;
		safety_assert(zone->zn_free != NULL || zone->zn_blocks == zone->zn_cnt);
		safety_assert(NULL == zone->zn_free || zbelongs(zone, zone->zn_free));
		zunlock(zone);
		return zprepare(zone, blk);
	}

	/*
	 * Maybe we're under garbage collection?
	 *
	 * We don't test this first because garabage collection occurs infrequently
	 * and when it does, the main free list is NULL so we end-up here.
	 * That way, there is very little speed penalty on allocation for the
	 * nominal case.
	 */

	if G_UNLIKELY(zone->zn_gc != NULL)
		return zgc_zalloc(zone);

	/*
	 * No more free blocks, extend the zone.
	 */

	g_assert(zone->zn_blocks == zone->zn_cnt);

	/*
	 * Use first block from new extended zone.
	 */

	blk = zn_extend(zone);
	zone->zn_free = (char **) *blk;
	zone->zn_cnt++;
	safety_assert(NULL == zone->zn_free || zbelongs(zone, zone->zn_free));

	zunlock(zone);
	return zprepare(zone, blk);
}

#ifdef TRACK_ZALLOC
/**
 * Tracking version of zalloc().
 */
void *
zalloc_track(zone_t *zone, const char *file, int line)
{
	char *blk = zalloc(zone);
	char *p;

	p = ptr_add_offset(blk, -OVH_LENGTH + OVH_TRACK_OFFSET);
	*(char const **) p = short_filename(file);
	p += sizeof(char *);
	*(int *) p = line;

	return blk;
}

/**
 * Log information about block, `p' being the physical start of the block, not
 * the user part of it.  The block is known to be of size `size' and should
 * be also recorded in the `leakset' for summarizing of all the leaks.
 */
static void
zblock_log(const char *p, size_t size, void *leakset)
{
	const char *uptr;			/* User pointer */
	const char *file;
	unsigned line;
	char ago[32];

	STATIC_ASSERT(OVH_ZONE_SAFE_LEN > 0);	/* Ensures ZONE_SAFE is on */

	uptr = const_ptr_add_offset(p, OVH_LENGTH);

	{
		const char *q = const_ptr_add_offset(p, OVH_TRACK_OFFSET);
		file = *(char **) q;
		q += sizeof(char *);
		line = *(int *) q;
	}

#ifdef MALLOC_FRAMES
	if (not_leaking != NULL && hash_table_lookup(not_leaking, uptr)) {
		s_message("block %p from \"%s:%u\" marked as non-leaking",
			uptr, file, line);
		return;
	}
#endif
#ifdef MALLOC_TIME
	{
		const time_t *t = const_ptr_add_offset(p, OVH_TIME_OFFSET);
		str_bprintf(ARYLEN(ago), " [%s]",
			short_time_ascii(delta_time(tm_time(), *t)));
	}
#else
	ago[0] = '\0';
#endif

	s_warning("leaked %zu-byte block %p from \"%s:%u\"%s",
		size, uptr, file, line, ago);

#ifdef MALLOC_FRAMES
	{
		const void *q = const_ptr_add_offset(p, OVH_FRAME_OFFSET);
		const struct frame *f = *(struct frame **) q;

		if (f != INVALID_FRAME_PTR) {
			leak_stack_add(leakset, size, f->ast);
		} else {
			s_warning("%s(): frame pointer suggests "
				"%zu-byte block %p was freed?",
				G_STRFUNC, size, uptr);
		}
	}
#endif

	leak_add(leakset, size, file, line);
}

/**
 * Go through the whole zone and dump all the used blocks.
 */
static void
zdump_used(const zone_t *zone, void *leakset)
{
	unsigned used = 0;
	const struct subzone *sz;
	const char *p;

	STATIC_ASSERT(OVH_ZONE_SAFE_LEN > 0);	/* Ensures ZONE_SAFE is on */

	for (sz = &zone->zn_arena; sz; sz = sz->sz_next) {
		const char *end;

		p = sz->sz_base;
		end = p + sz->sz_size;

		while (p < end) {
			if (*(const char **) p == BLOCK_USED) {
				used++;
				zblock_log(p, zone->zn_size, leakset);
			}
			p += zone->zn_size;
		}
	}

	if (used != zone->zn_cnt) {
		s_warning("BUG: "
			"found %u used block%s, but %zu-byte zone said it was holding %u",
			used, plural(used), zone->zn_size, zone->zn_cnt);
	}
}
#endif	/* TRACK_ZALLOC */

#if defined(TRACK_ZALLOC) || defined(MALLOC_FRAMES)
/**
 * Flag object ``o'' as "not leaking" if not freed at exit time.
 * @return argument ``o''.
 */
void *
zalloc_not_leaking(const void *o)
{
	const void *u;

	/*
	 * Before recording a pointer as non-leaking, we can't make sure we're
	 * called with a used zalloc() block: we could be invoked on a malloc'ed()
	 * object or worse, the result of a vmm_alloc(). So we can't just backtrack
	 * in memory and look for some header.
	 */

	ZLEAK_LOCK;

	if (NULL == not_leaking)
		not_leaking = hash_table_new();

	/*
	 * If object was allocated through halloc(), the used pointer (the one seen
	 * outside of halloc()) is not the start of the allocated block.  For the
	 * purpose of leak tracking, we track physical block start.
	 */

	if (G_LIKELY(alloc_used_to_real != NULL))
		u = hash_table_lookup(alloc_used_to_real, o);
	else
		u = NULL;		/* Very early in startup */

	hash_table_insert(not_leaking, u != NULL ? u : o, GINT_TO_POINTER(1));

	ZLEAK_UNLOCK;

	return deconstify_pointer(o);
}

/**
 * Records the mapping between the user-visible address of the allocated block,
 * as returned by halloc(), or any other header-using allocation routine based
 * on zalloc() for that matter, and the start of the physical block.
 */
void
zalloc_shift_pointer(const void *allocated, const void *used)
{
	g_assert(ptr_cmp(allocated, used) < 0);

	ZLEAK_LOCK;

	if (alloc_used_to_real == NULL) {
		alloc_used_to_real = hash_table_new();
		alloc_real_to_used = hash_table_new();
	}

	hash_table_insert(alloc_used_to_real, used, allocated);
	hash_table_insert(alloc_real_to_used, allocated, used);

	ZLEAK_UNLOCK;
}
#endif	/* TRACK_ZALLOC || MALLOC_FRAMES */

/**
 * Check that we are not attempting to perform an operation for a block in
 * the wrong zone and that the block is indeed still allocated.
 *
 * @param zone		the zone to which the pointer must belong
 * @param ptr		address of block
 * @param what		what we are trying to do ("free block", "move block", ...)
 */
#ifdef ZONE_ZAFE
static inline void
zcheck(zone_t *zone, void *ptr, const char *what)
{
	char **tmp;

	/* Go back at leading magic, also the start of the block */
	tmp = ptr_add_offset(ptr, -OVH_LENGTH + OVH_ZONE_SAFE_OFFSET);

	if G_UNLIKELY(tmp[0] != BLOCK_USED) {
		const zone_t *ozone = (zone_t *) tmp[1];
		zframe_dump(ptr, "block already freed");
		s_error("trying to %s %p twice (in %s %zu-byte zone)",
			what, ptr, ozone == zone ? "proper" :
				ZONE_MAGIC == ozone->zn_magic ? "wrong" : "invalid",
			ZONE_MAGIC == ozone->zn_magic ? zone_size(ozone) : 0);
	}
	if G_UNLIKELY(tmp[1] != (char *) zone) {
		const zone_t *ozone = (zone_t *) tmp[1];
		zframe_dump(ptr, "block allocated");
		s_error("trying to %s %p to wrong %zu-byte zone %p, "
			"allocated in %zu-byte zone %p",
			what, ptr, zone_size(zone), zone,
			ZONE_MAGIC == ozone->zn_magic ? zone_size(ozone) : 0, ozone);
	}
}
#else	/* !ZONE_SAFE */
#define zcheck(z,p,w)
#endif	/* ZONE_SAFE */

/**
 * Return user pointer to (already locked) zone.
 */
static inline void
zreturn(zone_t *zone, void *ptr)
{
	char **head;

	zcheck(zone, ptr, "free block");

#ifdef MALLOC_FRAMES
	{
		struct frame **p = ptr_add_offset(ptr, -OVH_LENGTH + OVH_FRAME_OFFSET);
		*p = INVALID_FRAME_PTR;
	}
#endif
#ifdef ZONE_FRAMES
	{
		struct stackatom const **p =
			ptr_add_offset(ptr, -OVH_LENGTH + OVH_FRAME_OFFSET);
#ifdef ZONE_SAFE
		struct stacktrace t;
		const struct stackatom *a;

		stacktrace_get_offset(&t, 1);	/* Remove ourselves from trace */
		a = zframe_mark_pointer(stacktrace_get_atom(&t));
		*p = a;							/* This is the freeing stack frame */
#else
		*p = INVALID_FRAME_PTR;
#endif	/* ZONE_SAFE */
	}
#endif	/* ZONE_FRAMES */
#if defined(TRACK_ZALLOC) || defined(MALLOC_FRAMES)
	if (not_leaking != NULL) {
		void *a = NULL;

		ZLEAK_LOCK;
		if (alloc_real_to_used != NULL) {
			a = hash_table_lookup(alloc_real_to_used, ptr);
		}
		hash_table_remove(not_leaking, a != NULL ? a : ptr);
		if (a != NULL) {
			hash_table_remove(alloc_real_to_used, ptr);
			hash_table_remove(alloc_used_to_real, a);
		}
		ZLEAK_UNLOCK;
	}
#endif

	safety_assert(zbelongs_uptr(zone, ptr));

	ptr = ptr_add_offset(ptr, -OVH_LENGTH);
	G_PREFETCH_W(ptr);
	G_PREFETCH_W(&zone->zn_free);
	G_PREFETCH_W(&zone->zn_cnt);

	if G_UNLIKELY(!uint_is_positive(zone->zn_cnt)) {
		zdescribe(zone);
		s_error("zone %p has no outstanding blocks to be freed", zone);
	}

	head = zone->zn_free;
	safety_assert(NULL == zone->zn_free || zbelongs(zone, zone->zn_free));

	if G_UNLIKELY(NULL == head && NULL != zone->zn_gc) {
		zgc_zfree(zone, ptr);
	} else {
		safety_assert(head != NULL || zone->zn_blocks == zone->zn_cnt);

		*(char **) ptr = (char *) head;			/* Will precede old head */
		zone->zn_free = ptr;					/* New free list head */
		zone->zn_cnt--;							/* To make zone gc easier */
	}
}

/**
 * Return block to its zone, hence freeing it. Previous content of the
 * block is lost.
 *
 * Since a zone consists of blocks with a fixed size, memory fragmentation
 * is not an issue. Therefore, the block is returned to the zone by being
 * inserted at the head of the free list.
 *
 * Warning: returning a block to the wrong zone may lead to disasters.
 */
void
zfree(zone_t *zone, void *ptr)
{
	g_assert(ptr);
	zone_check(zone);

	zlock(zone);
	zreturn(zone, ptr);
	zunlock(zone);

	ZSTATS_LOCK;
	zstats.freeings++;
	zstats.user_blocks--;
	zstats.user_memory -= zone->zn_size;
	ZSTATS_UNLOCK;
	memusage_remove_one(zone->zn_mem);
}

/**
 * Return list of blocks to its zone, hence freeing it. Previous content of the
 * block is lost.
 */
void
zfree_pslist(zone_t *zone, pslist_t *pl)
{
	size_t n = 0;
	pslist_t *l, *next;

	zone_check(zone);

	zlock(zone);

	for (l = pl; l != NULL; l = next, n++) {
		next = l->next;
		zreturn(zone, l);
	}

	zunlock(zone);

	ZSTATS_LOCK;
	zstats.freeings +=n;
	zstats.freeings_list++;
	zstats.freeings_list_blocks +=n;
	zstats.user_blocks -= n;
	zstats.user_memory -= zone->zn_size * n;
	ZSTATS_UNLOCK;

	memusage_remove_multiple(zone->zn_mem, n);
}

/**
 * Return list of blocks to its zone, hence freeing it. Previous content of the
 * block is lost.
 */
void
zfree_eslist(zone_t *zone, eslist_t *el)
{
	size_t n;
	void *p, *next;

	zone_check(zone);

	zlock(zone);

	for (n = 0, p = eslist_head(el); p != NULL; p = next, n++) {
		next = eslist_next_data(el, p);
		zreturn(zone, p);
	}

	zunlock(zone);

	g_assert(n == eslist_count(el));

	ZSTATS_LOCK;
	zstats.freeings +=n;
	zstats.freeings_list++;
	zstats.freeings_list_blocks +=n;
	zstats.user_blocks -= n;
	zstats.user_memory -= zone->zn_size * n;
	ZSTATS_UNLOCK;

	memusage_remove_multiple(zone->zn_mem, n);
}
#endif	/* !REMAP_ZALLOC */

/**
 * Cram a new zone in chunk.
 *
 * A zone consists of linked blocks, where the address of the next free block
 * is written in the first bytes of each free block.
 *
 * The first block in the arena will be the first free block.
 */
static void
zn_cram(const zone_t *zone, void *arena, size_t len)
{
	char **next = arena, *p = arena;
	size_t size = zone->zn_size;
	void *last = ptr_add_offset(arena, len - size);

	g_assert(len >= size);

	while (ptr_cmp(&p[size], last) <= 0) {
		next = cast_to_void_ptr(p);
		p = *next = &p[size];
	}
	next = cast_to_void_ptr(p);
	*next = NULL;
}

static void
subzone_alloc_arena(struct subzone *sz, size_t size)
{
	sz->sz_size = round_pagesize(size);
	sz->sz_base = vmm_core_alloc(sz->sz_size);
	sz->sz_ctime = tm_time();

	ZSTATS_LOCK;
	zstats.subzones_allocated++;
	zstats.subzones_allocated_pages += vmm_page_count(sz->sz_size);
	ZSTATS_UNLOCK;
}

static void
subzone_free_arena(struct subzone *sz)
{
	ZSTATS_LOCK;
	zstats.subzones_freed++;
	zstats.subzones_freed_pages += vmm_page_count(sz->sz_size);
	ZSTATS_UNLOCK;

	vmm_core_free(sz->sz_base, sz->sz_size);
	sz->sz_base = NULL;
	sz->sz_size = 0;
}

static zone_t *
subzone_alloc_embedded(size_t size)
{
	struct subzone sz;
	zone_t *zone;

	ZERO(&sz);
	subzone_alloc_arena(&sz, size);

	zone = cast_to_void_ptr(sz.sz_base);	/* Zone at the head of subzone */
	ZERO(zone);
	zone->embedded = TRUE;

	sz.sz_base = ptr_add_offset(sz.sz_base, sizeof *zone);
	sz.sz_size -= sizeof *zone;

	zone->zn_arena = sz;	/* Struct copy */

	return zone;
}

static void
subzone_free_embedded(struct subzone *sz)
{
	zone_t *zone;

	sz->sz_base = ptr_add_offset(sz->sz_base, -(sizeof *zone));
	sz->sz_size += sizeof *zone;
	zone = cast_to_void_ptr(sz->sz_base);

	g_assert(zone->embedded);

	subzone_free_arena(sz);
}

/*
 * Is subzone held in a virtual memory region that could be relocated or
 * is a standalone fragment?
 */
static inline bool
subzone_is_fragment(const struct subzone *sz)
{
	if (sz->sz_size < compat_pagesize())
		return FALSE;

	return vmm_is_relocatable(sz->sz_base, sz->sz_size) ||
		vmm_is_fragment(sz->sz_base, sz->sz_size);
}

/**
 * Get rid of additional subzones.
 */
static void
zn_free_additional_subzones(zone_t *zone)
{
	struct subzone *sz = zone->zn_arena.sz_next;

	while (sz) {
		struct subzone *next = sz->sz_next;
		subzone_free_arena(sz);
		xfree(sz);
		sz = next;
	}

	zone->zn_arena.sz_next = NULL;
	zrange_clear(zone);
}

/**
 * Adjust the block size so that we minimize the amount of wasted
 * memory per subzone chunk and get blocks large enough to store possible
 * extra information when debugging.
 *
 * @param requested		the initially requested size
 * @param hint_ptr		points to suggested amount of blocks per zone
 * @param verbose		if TRUE, possibly log debugging information
 *
 * @return adjusted block size and updated hint value
 */
static size_t
zalloc_adjust_size(size_t requested, unsigned *hint_ptr, bool verbose)
{
	size_t rounded;
	size_t wasted;
	size_t size;
	size_t arena_size;
	unsigned hint = *hint_ptr;

	/*
	 * Make sure size is big enough to store the free-list pointer used to
	 * chain all free blocks. Also round it so that all blocks are aligned on
	 * the correct boundary.
	 */

	size = MAX(sizeof(char *), requested);

	/*
	 * To secure the accesses, we reserve a pointer on top to make the linking.
	 * This pointer is filled in with the BLOCK_USED tag, enabling zfree to
	 * detect duplicate frees of a given block (which are indeed disastrous
	 * if done at all and the error remains undetected: the free list is
	 * corrupted).
	 *
	 * When tracking allocation points, each block records the file and the
	 * line number where it was allocated from.
	 */

	size += OVH_LENGTH;

	size = zalloc_round(size);

	g_assert(size < MAX_ZONE_SIZE);	/* Must not request zones for big sizes */

	/*
	 * Make sure we have at least room for `hint' blocks in the zone,
	 * and that at the same time, the size is not greater than MAX_ZONE_SIZE.
	 */

	hint = (hint == 0) ? DEFAULT_HINT : hint;
	if (hint > MAX_ZONE_SIZE / size) {
		hint = MAX_ZONE_SIZE / size;
	}
	arena_size = size * hint;
	g_assert(arena_size <= MAX_ZONE_SIZE);

	rounded = round_pagesize(arena_size);
	hint = rounded / size;
	wasted = rounded - size * hint;

	/*
	 * If the selected block size would waste some memory at the end of the
	 * subzone arena (always a multiple of the system's page size), then
	 * increase the block size.
	 *
	 * With this strategy and a memory alignment of 4, we reduce the maximum
	 * amount of zones needed for walloc() (4KiB blocks max) from 1024 to 80!
	 * With a memory alignment of 8, we have only 60 zones instead of 512.
	 *
	 * Overall, we considerably reduce the memory overhead, since zones for
	 * larger block sizes tend to be "shared" (for instance, block sizes
	 * ranging from 3076 to 3184 are all rounded up to 3184).
	 */

	if (wasted > 0) {
		size_t bsize = rounded / hint;
		size_t adjusted = (bsize / ZALLOC_ALIGNBYTES) * ZALLOC_ALIGNBYTES;

		g_assert(adjusted >= size);

		if (adjusted != size) {
			if (zalloc_debugging(0) && verbose) {
				s_debug("ZALLOC adjusting block size from %zu to %zu "
					"(%u blocks will waste %zu bytes at end of "
					"%zu-byte subzone)",
					requested, adjusted, hint, rounded - hint * adjusted,
					rounded);
			}
		} else {
			if (zalloc_debugging(0) && verbose) {
				s_debug("ZALLOC cannot adjust block size of %zu "
					"(%u blocks will waste %zu bytes at end of "
					"%zu-byte subzone)",
					requested, hint, rounded - hint * adjusted, rounded);
			}
		}

		size = adjusted;
	}

	*hint_ptr = hint;
	return size;
}

/**
 * Create a new zone able to hold `hint' items of 'size' bytes.
 *
 * If the ``zone'' parameter is NULL, create an embedded zone.
 */
static zone_t *
zn_create(zone_t *zone, size_t size, unsigned hint)
{
	g_assert(size > 0);
	g_assert(uint_is_non_negative(hint));

	/*
	 * Allocate the arena.
	 */

	if (NULL == zone)
		zone = subzone_alloc_embedded(size * hint);
	else
		subzone_alloc_arena(&zone->zn_arena, size * hint);

	/*
	 * Initialize zone descriptor.
	 */

	zone->zn_magic = ZONE_MAGIC;
	zone->zn_hint = hint;
	zone->zn_size = size;
	zone->zn_arena.sz_next = NULL;			/* Link keep track of arenas */
	zone->zn_cnt = 0;
	zone->zn_free = cast_to_void_ptr(zone->zn_arena.sz_base);
	zone->zn_refcnt = 1;
	zone->zn_subzones = 1;					/* One subzone to start with */
	zone->zn_blocks = zone->zn_hint;
	zone->zn_gc = NULL;
	zone->zn_stid = 0;
	spinlock_init(&zone->lock);

	zn_cram(zone, zone->zn_arena.sz_base, zone->zn_arena.sz_size);
	safety_assert(zbelongs(zone, zone->zn_free));

	return zone;
}

#ifndef REMAP_ZALLOC
/**
 * Extend zone by allocating a new zone chunk.
 *
 * @return the address of the first new free block within the extended
 *         chunk arena.
 */
static char **
zn_extend(zone_t *zone)
{
	struct subzone *sz;		/* New sub-zone */

	g_assert(spinlock_is_held(&zone->lock));

	XMALLOC(sz);
	subzone_alloc_arena(sz, zone->zn_size * zone->zn_hint);
	zrange_clear(zone);

	if (NULL == sz->sz_base)
		s_error("cannot extend %zu-byte zone", zone->zn_size);

	zone->zn_free = cast_to_void_ptr(sz->sz_base);
	sz->sz_next = zone->zn_arena.sz_next;
	zone->zn_arena.sz_next = sz;		/* New subzone at head of list */
	zone->zn_subzones++;
	zone->zn_oversized = 0;				/* Just extended, cannot be oversized */
	zone->zn_blocks += zone->zn_hint;

	zn_cram(zone, sz->sz_base, sz->sz_size);
	safety_assert(zbelongs(zone, zone->zn_free));

	return zone->zn_free;
}

/**
 * Shrink zone by discarding all subzones but the first.
 * Can only be called on zones with no allocated blocks.
 */
static void
zn_shrink(zone_t *zone)
{
	unsigned old_subzones;

	g_assert(spinlock_is_held(&zone->lock));
	g_assert(0 == zone->zn_cnt);		/* No blocks used */

	if (zalloc_debugging(1)) {
		s_debug("ZGC %zu-byte zone %p shrunk: "
			"freeing %u subzone%s of %zuKiB (%u blocks each)",
			zone->zn_size, (void *) zone,
			zone->zn_subzones - 1, 2 == zone->zn_subzones ? "" : "s",
			zone->zn_arena.sz_size / 1024, zone->zn_hint);
	}

	old_subzones = zone->zn_subzones;
	zn_free_additional_subzones(zone);

	ZSTATS_LOCK;
	zstats.zgc_excess_zones_freed += old_subzones - zone->zn_subzones;
	zstats.zgc_shrinked++;
	ZSTATS_UNLOCK;

	zone->zn_subzones = 1;				/* One subzone remains */
	zone->zn_blocks = zone->zn_hint;
	zone->zn_free = cast_to_void_ptr(zone->zn_arena.sz_base);
	zone->zn_oversized = 0;

	/* Recreate free list */
	zn_cram(zone, zone->zn_arena.sz_base, zone->zn_arena.sz_size);
	safety_assert(zbelongs(zone, zone->zn_free));
}
#endif	/* !REMAP_ZALLOC */

/**
 * Create a new zone able to hold items of 'size' bytes. Returns
 * NULL if no new zone can be created.
 *
 * The hint argument is to be construed as the average amount of objects
 * that are to be created per zone chunks. That is not the total amount of
 * expected objects of a given type. Leaving it a 0 selects the default hint
 * value.
 *
 * @param size			the (already adjusted) block size
 * @param hint			the expected amount of blocks per chunk.
 *
 * @return a new zone.
 */
static zone_t *
zcreate_internal(size_t size, unsigned hint, bool embedded)
{
	zone_t *zone;			/* Zone descriptor */

	zone = embedded ? NULL : xmalloc0(sizeof *zone);
	zone = zn_create(zone, size, 0 == hint ? DEFAULT_HINT : hint);

#ifndef REMAP_ZALLOC
	if (zgc_always(zone)) {
		zlock(zone);
		if (NULL == zone->zn_gc && vmm_is_long_term())
			zgc_allocate(zone);
		zunlock(zone);
	}
#endif

	return zone;
}

/**
 * Create a new zone able to hold items of 'size' bytes. Returns
 * NULL if no new zone can be created.
 *
 * The hint argument is to be construed as the average amount of objects
 * that are to be created per zone chunks. That is not the total amount of
 * expected objects of a given type. Leaving it a 0 selects the default hint
 * value.
 */
zone_t *
zcreate(size_t size, unsigned hint, bool embedded)
{
	size = zalloc_adjust_size(size, &hint, TRUE);

	return zcreate_internal(size, hint, embedded);
}

/**
 * Destroy a (locked) zone chunk.
 */
static void
zdestroy_physical(zone_t *zone)
{
	if (zone->zn_cnt) {
		s_warning("destroyed zone (%zu-byte blocks) still holds %u entr%s",
			zone->zn_size, zone->zn_cnt, plural_y(zone->zn_cnt));
#ifdef TRACK_ZALLOC
		zdump_used(zone, z_leakset);
#endif
	}

#ifndef REMAP_ZALLOC
	if (zone->zn_gc)
		zgc_dispose(zone);
#endif

	zn_free_additional_subzones(zone);

	/*
	 * An embedded zone has no separate zone descriptor: it is embedded at
	 * the start of the first subzone.
	 *
	 * Such zones are never used by zget(), so they cannot be held in the
	 * hash table by zone size.
	 */

	if (!zone->embedded) {
		subzone_free_arena(&zone->zn_arena);

		if (!zalloc_closing)
			hash_table_remove(zt, zone);
	}

	/*
	 * If the zone is private, unlock it to avoid spinlock_destroy()
	 * complaining about the lock being not registered (since a private
	 * zone is not really locked).
	 */

	if (zone->private)
		zunlock(zone);

	spinlock_destroy(&zone->lock);

	if (zone->embedded) {
		subzone_free_embedded(&zone->zn_arena);
	} else {
		xfree(zone);
	}
}

/**
 * Destroy a zone chunk by releasing its memory to the system if possible.
 */
void
zdestroy(zone_t *zone)
{
	zone_check(zone);
	g_assert(uint_is_positive(zone->zn_refcnt));

	/*
	 * A zone can be used by many different parts of the code, through
	 * calls to zget().  Therefore, only destroy the zone when all references
	 * are gone.
	 */

	zlock(zone);

	if (!atomic_uint_dec_is_zero(&zone->zn_refcnt)) {
		zunlock(zone);
		return;
	}

	zdestroy_physical(zone);
}

/**
 * Destroy a zone if it is referenced once and holds no items.
 *
 * @return TRUE if zone was physically destroyed.
 */
bool
zdestroy_if_empty(zone_t *zone)
{
	zone_check(zone);
	g_assert(uint_is_positive(zone->zn_refcnt));

	zlock(zone);

	if (1 != atomic_uint_get(&zone->zn_refcnt) || zone->zn_cnt != 0) {
		zunlock(zone);
		return FALSE;
	}

	zdestroy_physical(zone);
	return TRUE;
}

/**
 * Get a zone suitable for allocating blocks of 'size' bytes.
 * `hint' represents the desired amount of blocks per subzone.
 *
 * This is mainly intended for external clients who want distinct zones for
 * distinct sizes, yet may share zones for distinct albeit same-sized blocks.
 * For instance, walloc() requests zones for power-of-two sizes and uses
 * zget() to get the zone, instead of zcreate() to maximize sharing.
 */
zone_t *
zget(size_t size, unsigned hint, bool private)
{
	static spinlock_t zget_slk = SPINLOCK_INIT;
	zone_t *zone;
	zone_t key;

	/*
	 * Allocate hash table if not already done!
	 */

	spinlock(&zget_slk);

	if G_UNLIKELY(zt == NULL) {
		zt = hash_table_new_full(zone_hash, zone_eq);
		hash_table_thread_safe(zt);
	}

	/*
	 * Adjust the requested size to ensure proper alignment of allocated
	 * memory blocks and minimize the amount of wasted space in subzones.
	 */

	size = zalloc_adjust_size(size, &hint, TRUE);

	key.zn_size = size;
	key.private = booleanize(private);
	key.zn_stid = private ? thread_small_id() : 0;

	zone = hash_table_lookup(zt, &key);

	/*
	 * Supplied hint value is ignored if a zone already exists for that size
	 */

	if G_LIKELY(zone != NULL) {
		atomic_uint_inc(&zone->zn_refcnt);
		goto found;					/* Found a zone for matching size! */
	}

	/*
	 * No zone of the corresponding size already, create a new one!
	 */

	zone = zcreate_internal(size, hint, FALSE);

	if (private) {
		zone->private = TRUE;
		zone->zn_stid = key.zn_stid;
	}

	/*
	 * Insert new zone in the hash table so that we can return it to other
	 * clients requesting a similar size. If we can't insert it, it's not
	 * a fatal error, only a warning: we can always allocate a new zone next
	 * time!
	 */

	hash_table_insert(zt, zone, zone);

found:
	spinunlock(&zget_slk);

	if (zalloc_debugging(1)) {
		size_t count = hash_table_count(zt);
		size_t buckets = hash_table_buckets(zt);
		double clustering = hash_table_clustering(zt);
		s_info("clustering in zalloc()'s zone table is %F for %zu/%zu items "
			"(%zu buckets, optimal spread = %F items/bucket)",
			clustering, count, hash_table_capacity(zt), buckets,
			(double) count / buckets);
	}

	zone_check(zone);

	return zone;
}

/**
 * Move block in the same zone to an hopefully better place.
 * @return new location for block.
 */
void *
zmove(zone_t *zone, void *p)
{
	zone_check(zone);

	/*
	 * If there is no garbage collection turned on for the zone, keep it as-is.
	 */

	ZSTATS_INCX(zmove_attempts);

	zcheck(zone, p, "move block");

	if G_LIKELY(NULL == zone->zn_gc)
		return p;

#ifdef REMAP_ZALLOC
	return p;
#else
	return zgc_zmove(zone, p);
#endif
}

/**
 * Move data from old block to new block and free old block.
 * Both blocks must be used and belong to the same zone.
 *
 * @param zone		the zone to which blocks belong
 * @param o			the old block
 * @param n			the new block
 *
 * @return location of new block for convenience.
 */
void *
zmoveto(zone_t *zone, void *o, void *n)
{
	void *ostart, *nstart;

	zone_check(zone);
	zcheck(zone, o, "move data from block");
	zcheck(zone, n, "move data to block");

	ZSTATS_INCX(zmove_successful_smart);

	/*
	 * Also copy possible overhead (already included in zone's block size),
	 * in order to keep original meta info attached to the old block.
	 */

	ostart = ptr_add_offset(o, -OVH_LENGTH);
	nstart = ptr_add_offset(n, -OVH_LENGTH);
	memcpy(nstart, ostart, zone->zn_size);

	/*
	 * Do not call zfree() as we do not want to account for freeing a block!
	 */

	zlock(zone);
	zreturn(zone, o);
	zunlock(zone);

	return n;
}

/**
 * Iterator callback on hash table.
 */
static void
free_zone(const void *u_key, void *value, void *u_data)
{
	zone_t *zone = value;

	g_assert(uint_is_positive(zone->zn_refcnt));
	(void) u_key;
	(void) u_data;

	if (zone->zn_refcnt > 1) {
		s_warning("zone (%zu-byte blocks) still had %u references",
			zone->zn_size, zone->zn_refcnt);
		zone->zn_refcnt = 1;
	}

	zdestroy(zone);
}

/**
 * Close the zone allocator, destroying all the remaining zones regardless
 * of their reference count.
 */
void G_COLD
zclose(void)
{
	if (NULL == zt)
		return;

	zalloc_closing = TRUE;
	hash_table_foreach(zt, free_zone, NULL);
	hash_table_destroy(zt);
	zt = NULL;

#ifdef TRACK_ZALLOC
	leak_dump(z_leakset);
	leak_close_null(&z_leakset);
#endif

#ifdef MALLOC_FRAMES
	if (zalloc_frames != NULL) {
		extern void hash_table_destroy_real(hash_table_t *ht);
		size_t frames = hash_table_count(zalloc_frames);
		s_message("zalloc() tracked %zu distinct stack frame%s",
			frames, plural(frames));
		hash_table_destroy_real(zalloc_frames);
		zalloc_frames = NULL;
	}
#endif
#if defined(TRACK_ZALLOC) || defined(MALLOC_FRAMES)
	if (not_leaking != NULL) {
		size_t blocks = hash_table_count(not_leaking);
		s_message("zalloc() had %zu block%s registered as not-leaking",
			blocks, plural(blocks));
		hash_table_destroy(not_leaking);
		not_leaking = NULL;
	}
	if (alloc_used_to_real != NULL) {
		size_t blocks = hash_table_count(alloc_used_to_real);
		s_message("zalloc() had %zu block%s registered for address shifting",
			blocks, plural(blocks));
		hash_table_destroy(alloc_used_to_real);
		if (hash_table_count(alloc_real_to_used) != blocks) {
			s_warning("zalloc() had count mismatch in address shifting tables");
		}
		hash_table_destroy(alloc_real_to_used);
		alloc_used_to_real = alloc_real_to_used = NULL;
	}
#endif
}

/**
 * Set debug level.
 */
void
set_zalloc_debug(uint32 level)
{
	zalloc_debug = level;
}

/**
 * Whether zones should always stay in GC mode.
 *
 * The advantage of having all zones in GC mode is that allocation will be
 * always done in a subzone where we have already allocated some other blocks,
 * since fully empty subzones are reclaimed.  This minimizes the risk of having
 * rather permanent blocks allocated in all the subzones, preventing collection
 * since unfortunately we cannot move allocated blocks around!
 *
 * The disadvantage is that each free has to perform a binary search on the
 * subzone array to find the proper subzone to return the block to.  However,
 * with the current size adjustments performed to minimize waste in subzones,
 * we allocate only 80 zones for walloc() with an alignment to 4 bytes.  That
 * means we perform at most 7 checks, so it's only slightly more costly.
 *
 * What this strategy buys us however is greater chances of allocating less
 * subzones, resulting in a smaller memory footprint.  For long-running
 * processes, this is a good property.
 */
void
set_zalloc_always_gc(bool val)
{
	zalloc_always_gc = val;
}

#ifndef REMAP_ZALLOC

/***
 *** Garbage collector
 ***/

#define ZN_OVERSIZE_THRESH	90

/**
 * Global zone garbage collector state.
 */
static struct {
	unsigned subzone_freed;			/**< Amount of subzones freed this run */
	bool running;					/**< Garbage collector is running */
} zgc_context;

#define ZGC_SUBZONE_MINLIFE		5	/**< Do not free too recent subzone */
#define ZGC_SUBZONE_FREEMAX		64	/**< Max # of subzones freed in a run */
#define ZGC_SUBZONE_OVERBASE	48	/**< Initial base when CPU overloaded */

static unsigned zgc_zone_cnt;		/**< Zones in garbage collecting mode */

/**
 * Compare two subzinfo based on base address -- xsort() callback.
 */
static int
subzinfo_cmp(const void *a, const void *b)
{
	const struct subzinfo *sa = a;
	const struct subzinfo *sb = b;

	return ptr_cmp(sa->szi_base, sb->szi_base);
}

/**
 * Lookup subzone holding the block.
 *
 * If ``low_ptr'' is non-NULL, it is written with the index where insertion
 * of a new item should happen (in which case the returned value must be NULL).
 *
 * @return a pointer to the found subzone information, NULL if not found.
 */
static struct subzinfo * G_HOT
zgc_find_subzone(struct zone_gc *zg, void *blk, unsigned *low_ptr)
{
	const struct subzinfo
		*array = zg->zg_subzinfo,
		*low = &array[0],
		*high = &array[zg->zg_zones - 1],
		*mid;
	const char * const key = blk;

	if G_UNLIKELY(0 == zg->zg_zones) {
		if (low_ptr != NULL)
			*low_ptr = 0;
		return NULL;
	}

	/* Binary search */

	for (;;) {
		if G_UNLIKELY(low > high) {
			mid = NULL;		/* Not found */
			break;
		}

		mid = low + (high - low) / 2;

		if (key >= mid->szi_end)
			low = mid + 1;
		else if (key < mid->szi_base)
			high = mid - 1;		/* -1 OK since pointers cannot reach page 0 */
		else
			break;	/* Found */
	}

	if (low_ptr != NULL)
		*low_ptr = low - &array[0];

	return deconstify_pointer(mid);
}

/**
 * Check whether address falls within the subzone boundaries.
 */
static inline bool G_HOT
zgc_within_subzone(const struct subzinfo *szi, const void *p)
{
	struct subzone *sz;

	g_assert(szi != NULL);
	g_assert(szi->szi_sz != NULL);

	sz = szi->szi_sz;

	g_assert(sz->sz_base == szi->szi_base);
	g_assert(ptr_diff(szi->szi_end, szi->szi_base) == sz->sz_size);

	return ptr_cmp(p, szi->szi_base) >= 0 && ptr_cmp(p, szi->szi_end) < 0;
}

/**
 * Add a new subzone in the garbage collection structure, where ``blk'' is
 * the first free block in the subzone.
 *
 * @return pointer to the inserted subzone info.
 */
static struct subzinfo *
zgc_insert_subzone(const zone_t *zone, struct subzone *sz, char **blk)
{
	struct zone_gc *zg = zone->zn_gc;
	unsigned low;
	struct subzinfo *szi;

	/*
	 * Find index at which we must insert the new zone in the sorted array.
	 */

	if (zgc_find_subzone(zg, blk, &low))
		s_error("new subzone cannot be present in the array");

	/*
	 * Insert new subzone at `low'.
	 */

	zg->zg_zones++;
	XREALLOC_ARRAY(zg->zg_subzinfo, zg->zg_zones);

	g_assert(uint_is_non_negative(low));

	ARRAY_MAKEROOM(zg->zg_subzinfo, low, zg->zg_zones - 1, zg->zg_zones);

	szi = &zg->zg_subzinfo[low];
	szi->szi_base = sz->sz_base;
	szi->szi_end = &sz->sz_base[sz->sz_size];
	szi->szi_free_cnt = zone->zn_hint;
	szi->szi_free = blk;
	szi->szi_sz = sz;

	g_assert(zgc_within_subzone(szi, blk));
	safety_assert(zgc_subzinfo_valid(zone, szi));

	if (addr_grows_upwards) {
		if (zg->zg_free > low)
			zg->zg_free = low;		/* The subzone we have just added */
	} else {
		if (zg->zg_free <= low)
			zg->zg_free = low;		/* The subzone we have just added */
		else
			zg->zg_free++;			/* Everything above was shifted up */
	}

	g_assert(uint_is_non_negative(zg->zg_free) && zg->zg_free < zg->zg_zones);

	return szi;
}

/**
 * Remove subzone info from the garbage collection structure.
 */
static void
zgc_remove_subzone(const zone_t *zone, struct subzinfo *szi)
{
	struct zone_gc *zg = zone->zn_gc;

	g_assert(uint_is_positive(zg->zg_zones));

	zg->zg_zones--;

	if G_UNLIKELY(szi == &zg->zg_subzinfo[zg->zg_zones]) {
		/* Removing trailing zone */
		if (zg->zg_free == zg->zg_zones && 0 != zg->zg_zones)
			zg->zg_free--;
	} else {
		unsigned i = szi - zg->zg_subzinfo;

		g_assert(uint_is_non_negative(i));
		g_assert(i < zg->zg_zones);

		ARRAY_REMOVE(zg->zg_subzinfo, i, zg->zg_zones + 1);

		if (zg->zg_free > i)
			zg->zg_free--;
	}

	g_assert(uint_is_non_negative(zg->zg_free));
	g_assert(0 == zg->zg_zones || zg->zg_free < zg->zg_zones);
	g_assert(uint_is_non_negative(zg->zg_zones));
	g_assert(zg->zg_zones != 1 || &zone->zn_arena == zg->zg_subzinfo[0].szi_sz);
}

/**
 * Update subzone information when arena was moved.
 *
 * @note
 * The free blocks are already chained and szi->szi_free already points to the
 * first available block in the new arena.
 *
 * @attention
 * Upon return, the `szi' value MUST NOT be used again.
 *
 * @param zone		the zone to which subzone belongs to
 * @param szi		subzone whose arena was moved
 * @param nbase		new arena base
 */
static void
zgc_subzone_moved(zone_t *zone, struct subzinfo *szi, char *nbase)
{
	struct zone_gc *zg = zone->zn_gc;
	struct subzone *sz = szi->szi_sz;

	g_assert(szi != NULL);
	g_assert(zg != NULL);
	g_assert(szi->szi_base == sz->sz_base);
	g_assert(szi->szi_base != nbase);		/* Arena was moved but not updated */
	g_assert(!zgc_within_subzone(szi, szi->szi_free));	/* Not yet! */

	/*
	 * Update memory addresses in relevant subzone structures.
	 */

	zrange_clear(zone);
	sz->sz_base = szi->szi_base = nbase;
	szi->szi_end = &sz->sz_base[sz->sz_size];

	/*
	 * Make sure the contract is fullfilled: the first free block must belong
	 * to the arena!
	 */

	g_assert(zgc_within_subzone(szi, szi->szi_free));

	if (zalloc_debugging(4)) {
		s_debug("ZGC %zu-byte zone %p moved %u blocks in [%p, %p]",
			zone->zn_size, (void *) zone,
			zone->zn_hint, szi->szi_base, szi->szi_end);
	}

	/*
	 * Re-sort the subzone array now that the base of the current
	 * subzone has changed.
	 *
	 * NOTE: this changes `szi', since it moves around structures in the
	 * array, so we must no longer use the old `szi' upon return from this
	 * routine.
	 */

	xqsort(zg->zg_subzinfo, zg->zg_zones, sizeof *szi, subzinfo_cmp);

	/*
	 * We remember the index of the first subzinfo with free blocks to
	 * accelerate zgc_zalloc().  Since we just moved a zone and we do not
	 * want to re-scan the whole set of zones, simply reset the index
	 * to the initial default value.
	 */

	zg->zg_free = addr_grows_upwards ? 0 : zg->zg_zones - 1;
}

/**
 * Defragment a subzone in the VM space by attempting to move it to a better
 * location.
 */
static void
zgc_subzone_defragment(zone_t *zone, struct subzinfo *szi)
{
	struct zone_gc *zg = zone->zn_gc;
	struct subzone *sz = szi->szi_sz;
	char *nbase;

	g_assert(szi != NULL);
	g_assert(zg != NULL);
	g_assert(equiv(&zone->zn_arena == sz, 1 == zone->zn_subzones));
	g_assert(szi->szi_free_cnt == zone->zn_hint);
	g_assert(szi->szi_base == sz->sz_base);

	/*
	 * Instead of testing whether subzone is a fragment by calling
	 * subzone_is_fragment(), we attempt to see whether we can move
	 * the arena around in the VM space.
	 * 		--RAM, 2017-11-26
	 */

	nbase = vmm_core_move(sz->sz_base, sz->sz_size);
	if (nbase == sz->sz_base)
		return;

	if (zalloc_debugging(1)) {
		time_delta_t life = delta_time(tm_time(), sz->sz_ctime);
		s_debug("ZGC %zu-byte zone %p: %ssubzone "
			"[%p, %p] %zuKiB, %u blocks, lifetime %s, moved to %p",
			zone->zn_size, (void *) zone,
			&zone->zn_arena == sz ? "first " : "extra ",
			szi->szi_base, szi->szi_end - 1,
			ptr_diff(szi->szi_end, szi->szi_base) / 1024,
			zone->zn_hint, compact_time(life), nbase);
	}

	zg->zg_zone_defragmented++;

	ZSTATS_INCX(zgc_zones_defragmented);

	/*
	 * Rebuild free list for the new arena address.
	 */

	zn_cram(zone, nbase, sz->sz_size);	/* First free block is first block */
	szi->szi_free = (char **) nbase;	/* First block */

	zgc_subzone_moved(zone, szi, nbase);
}

/**
 * Free up a subzone which is completely empty.
 *
 * @return TRUE if OK, FALSE if we did not free it.
 */
static bool
zgc_subzone_free(zone_t *zone, struct subzinfo *szi)
{
	struct zone_gc *zg = zone->zn_gc;
	struct subzone *sz = zone->zn_arena.sz_next;

	g_assert(szi != NULL);
	g_assert(zg != NULL);
	g_assert(equiv(NULL == sz, 1 == zone->zn_subzones));
	g_assert(zone->zn_blocks >= zone->zn_hint);

	/*
	 * Do not free the subzone if that would leave us with no more free blocks
	 * in the whole zone.
	 *
	 * To help defragmenting the VM space, if the subzone is actually a
	 * fragment, attempt to move it around.
	 */

	if G_UNLIKELY(1 == zone->zn_subzones) {
		g_assert(zone->zn_blocks == zone->zn_hint);
		ZSTATS_INCX(zgc_last_zone_kept);
		goto defragment;
	}

	/*
	 * Regardless of its age, if the subzone is a memory fragment, release it.
	 */

	if (subzone_is_fragment(szi->szi_sz)) {
		if (zalloc_debugging(1)) {
			time_delta_t life = delta_time(tm_time(), sz->sz_ctime);
			s_debug("ZGC %zu-byte zone %p: %ssubzone "
				"[%p, %p] %zuKiB, %u blocks, lifetime %s is a fragment, "
				"attempting release",
				zone->zn_size, (void *) zone,
				&zone->zn_arena == szi->szi_sz ? "first " : "extra ",
				szi->szi_base, szi->szi_end - 1,
				ptr_diff(szi->szi_end, szi->szi_base) / 1024,
				zone->zn_hint, compact_time(life));
		}

		ZSTATS_INCX(zgc_fragments_freed);
		goto release_zone;
	}

	/*
	 * To accomodate rapid zalloc()/zfree() usage patterns for a zone,
	 * do not release a subzone that was allocated too recently.
	 *
	 * This strategy imposes us to flag the zone as requiring a complete
	 * subzone scan at the next GC run because otherwise we could be left with
	 * many free zones after massive zfree() calls.  That scan will only
	 * happen if we have more free blocks in the zone than the amount of
	 * blocks held in a subzone, or it will be cancelled (since by definition
	 * we cannot have a free subzone when we have less than a subzone worth).
	 */

	if (delta_time(tm_time(), szi->szi_sz->sz_ctime) < ZGC_SUBZONE_MINLIFE) {
		zg->zg_flags |= ZGC_SCAN_ALL;
		goto defragment;
	}

	if (
		zone->zn_blocks - zone->zn_cnt == zone->zn_hint &&
		delta_time(tm_time(), szi->szi_sz->sz_ctime) < 5 * ZGC_SUBZONE_MINLIFE
	) {
		zg->zg_flags |= ZGC_SCAN_ALL;
		goto defragment;
	}

	/* FALL THROUGH */

release_zone:

	/*
	 * If we have already freed our quota of subzones during this GC cycle,
	 * do not free the zone.
	 */

	if (
		zgc_context.running &&
		zgc_context.subzone_freed >= ZGC_SUBZONE_FREEMAX
	) {
		if (zalloc_debugging(3)) {
			s_debug("ZGC %zu-byte zone %p: hit subzone free limit",
				zone->zn_size, (void *) zone);
		}
		zg->zg_flags |= ZGC_SCAN_ALL;

		ZSTATS_INCX(zgc_free_quota_reached);
		return FALSE;
	}

	if (szi->szi_base == zone->zn_arena.sz_base) {

		g_assert(sz != NULL);	/* We know there are more than 1 subzone */

		if G_UNLIKELY(zone->embedded)
			return FALSE;		/* Can't free first subzone, holds the zone */

		if (zalloc_debugging(1)) {
			unsigned free_blocks = zone->zn_blocks - zone->zn_cnt -
				zone->zn_hint;
			time_delta_t life = delta_time(tm_time(), zone->zn_arena.sz_ctime);
			s_debug("ZGC %zu-byte zone %p: freeing first subzone "
				"[%p, %p] %zuKiB, %u blocks, lifetime %s "
				"(still has %u free block%s)",
				zone->zn_size, (void *) zone,
				szi->szi_base, szi->szi_end - 1,
				ptr_diff(szi->szi_end, szi->szi_base) / 1024,
				zone->zn_hint, compact_time(life),
				free_blocks, plural(free_blocks));
		}

		subzone_free_arena(&zone->zn_arena);
		zrange_clear(zone);
		zone->zn_arena = *sz;	/* Struct copy */
		{
			size_t i;

			for (i = 0; i < zg->zg_zones; i++) {
				struct subzinfo *s = &zg->zg_subzinfo[i];
				if (s->szi_sz == sz) {
					s->szi_sz = &zone->zn_arena;
					break;
				}
			}
		}
		xfree(sz);
	} else {
		unsigned n = 2;
		struct subzone *prev = &zone->zn_arena;

		while (sz) {
			struct subzone *next = sz->sz_next;

			if (sz->sz_base == szi->szi_base) {
				if (zalloc_debugging(1)) {
					unsigned free_blocks = zone->zn_blocks - zone->zn_cnt -
						zone->zn_hint;
					time_delta_t life = delta_time(tm_time(), sz->sz_ctime);
					s_debug("ZGC %zu-byte zone %p: freeing subzone #%u "
						"[%p, %p] %zuKiB, %u blocks, lifetime %s "
						"(still has %u free block%s)",
						zone->zn_size, (void *) zone, n,
						szi->szi_base, szi->szi_end - 1,
						ptr_diff(szi->szi_end, szi->szi_base) / 1024,
						zone->zn_hint, compact_time(life),
						free_blocks, plural(free_blocks));
				}
				subzone_free_arena(sz);
				zrange_clear(zone);
				xfree(sz);
				prev->sz_next = next;
				goto found;
			}

			prev = sz;
			sz = next;
			n++;
		}

		s_error("subzone to delete not found in list");
	}

found:

	zone->zn_blocks -= zone->zn_hint;
	zone->zn_subzones--;
	zgc_context.subzone_freed++;

	ZSTATS_INCX(zgc_zones_freed);

	/*
	 * Remove subzone info from sorted array.
	 */

	zg->zg_zone_freed++;
	zgc_remove_subzone(zone, szi);

	return TRUE;

defragment:
	zgc_subzone_defragment(zone, szi);
	return FALSE;
}

/**
 * Insert block into proper subzone's free list.
 * When the subzone is completely empty, free it.
 *
 * @return TRUE if block was inserted, FALSE if subzone was freed.
 */
static bool
zgc_insert_freelist(zone_t *zone, char **blk)
{
	struct zone_gc *zg = zone->zn_gc;
	struct subzinfo *szi;
	unsigned idx;

	G_PREFETCH_W(blk);
	G_PREFETCH_W(&zg->zg_free);

	szi = zgc_find_subzone(zg, blk, NULL);

	G_PREFETCH_W(&szi->szi_free_cnt);

	g_assert(szi != NULL);
	g_assert(zgc_within_subzone(szi, blk));
	safety_assert(zgc_subzinfo_valid(zone, szi));

	/*
	 * Whether we are going to free up the subzone or not, we put the block
	 * back to the freelist.  Indeed, zgc_subzone_free() will never accept
	 * to free up the first subzone if it is the only one remaining, so we
	 * don't want to lose the freed block should the subzone be kept.
	 */

	g_assert(NULL == szi->szi_free || zgc_within_subzone(szi, szi->szi_free));

	*blk = (char *) szi->szi_free;		/* Precede old head */
	szi->szi_free = blk;

	/*
	 * Remember index of first subzinfo with free blocks to accelerate
	 * zgc_zalloc().
	 */

	idx = szi - zg->zg_subzinfo;

	g_assert(uint_is_non_negative(idx) && idx < zg->zg_zones);

	/*
	 * Keep the first free zone index closest to the start of the
	 * VM address space so that we start to allocate blocks in subzones
	 * that are less likely to become fragments.
	 */

	if (addr_grows_upwards) {
		if (idx < zg->zg_free)
			zg->zg_free = idx;
	} else {
		if (idx > zg->zg_free)
			zg->zg_free = idx;
	}

	if (++szi->szi_free_cnt == zone->zn_hint)
		return !zgc_subzone_free(zone, szi);

	return TRUE;
}

/**
 * Allocate garbage collecting data structures for a zone.
 */
static void
zgc_allocate(zone_t *zone)
{
	struct zone_gc *zg;
	struct subzone *sz;
	struct subzinfo *szi;
	char **blk;
	unsigned dispatched = 0;
	unsigned subzones = 0;

	g_assert(NULL == zone->zn_gc);
	g_assert(zone->zn_blocks >= zone->zn_cnt);
	g_assert(spinlock_is_held(&zone->lock));

	if (zalloc_debugging(1)) {
		unsigned free_blocks = zone->zn_blocks - zone->zn_cnt;
		s_debug("ZGC %zu-byte zone %p: "
			"setting up garbage collection for %u subzone%s, %u free block%s",
			zone->zn_size, (void *) zone,
			zone->zn_subzones, plural(zone->zn_subzones),
			free_blocks, plural(free_blocks));
	}

	XMALLOC(zg);
	zg->zg_zones = zone->zn_subzones;
	XMALLOC_ARRAY(zg->zg_subzinfo, zg->zg_zones);
	zg->zg_zone_freed = 0;
	zg->zg_zone_defragmented = 0;
	zg->zg_start = tm_time();
	zg->zg_free = addr_grows_upwards ? 0 : zg->zg_zones - 1;
	zg->zg_flags = 0;

	zone->zn_gc = zg;

	/*
	 * Fill in the subzone information, enough for sorting the array.
	 */

	for (
		szi = zg->zg_subzinfo, sz = &zone->zn_arena;
		sz != NULL;
		sz = sz->sz_next, szi++
	) {
		char *start = sz->sz_base;
		char *end = start + sz->sz_size;

		g_assert(subzones < zone->zn_subzones);

		szi->szi_base = start;
		szi->szi_end = end;
		szi->szi_free_cnt = 0;
		szi->szi_free = NULL;
		szi->szi_sz = sz;

		subzones++;
	}

	g_assert(subzones == zone->zn_subzones);

	/*
	 * Sort the array by increasing subzone base addresses.
	 *
	 * Do not use qsort(), since it can malloc(), which could cause a
	 * deadlock when xmalloc() replaces the system's malloc(), should
	 * we re-enter the zone allocator on the already locked zone.
	 */

	xqsort(zg->zg_subzinfo, zg->zg_zones, sizeof *szi, subzinfo_cmp);

	/*
	 * Dispatch each free block to the proper subzone free list.
	 */

	while ((blk = zone->zn_free)) {
		zone->zn_free = (char **) *blk;
		dispatched++;
		if (!zgc_insert_freelist(zone, blk)) {
			g_assert(dispatched >= zone->zn_hint);
			dispatched -= zone->zn_hint;	/* Subzone removed */
		}
	}

	atomic_uint_inc(&zgc_zone_cnt);

	g_assert(dispatched == zone->zn_blocks - zone->zn_cnt);
	g_assert(NULL == zone->zn_free);
	g_assert(zone->zn_gc != NULL);
}

/**
 * Extend garbage-collected zone.
 *
 * @return new free block, removed from free list.
 */
static void *
zgc_extend(zone_t *zone)
{
	char **blk;
	struct subzone *sz;
	struct subzinfo *szi;

	g_assert(zone->zn_gc != NULL);
	g_assert(zone->zn_free == NULL);

	/*
	 * Extend the zone by allocating a new subzone.
	 */

	blk = zn_extend(zone);
	sz = zone->zn_arena.sz_next;		/* Allocated zone */

	g_assert(zone->zn_free != NULL);
	g_assert(cast_to_char_ptr(blk) == sz->sz_base);

	szi = zgc_insert_subzone(zone, sz, blk);
	szi->szi_free = (char **) *blk;		/* Use first block */
	szi->szi_free_cnt--;

	/* Added more than 1 block */
	g_assert(zgc_within_subzone(szi, blk));
	g_assert(szi->szi_free_cnt != 0 && zgc_within_subzone(szi, szi->szi_free));
	safety_assert(zgc_subzinfo_valid(zone, szi));

	if (zalloc_debugging(4)) {
		s_debug("ZGC %zu-byte zone %p extended by %u blocks in [%p, %p]",
			zone->zn_size, (void *) zone,
			zone->zn_hint, szi->szi_base, szi->szi_end - 1);
	}

	zone->zn_free = NULL;		/* In GC mode, we never use this */
	return blk;					/* First free block */
}

/**
 * Scan zone to see whether we have empty subzones that are old enough and
 * free them up provided that does not leave us with no more free blocks.
 */
static void
zgc_scan(zone_t *zone)
{
	struct zone_gc *zg = zone->zn_gc;
	unsigned i;
	bool must_continue = FALSE;

	g_assert(zg != NULL);
	g_assert(zone->zn_blocks >= zone->zn_cnt);
	g_assert(uint_is_non_negative(zg->zg_free));
	g_assert(spinlock_is_held(&zone->lock));

	if (zalloc_debugging(4)) {
		s_debug("ZGC %zu-byte zone %p scanned for free subzones: "
			"%u blocks, %u free (hint=%u, %u subzones)",
			zone->zn_size, (void *) zone,
			zone->zn_blocks, zone->zn_blocks - zone->zn_cnt, zone->zn_hint,
			zone->zn_subzones);
	}

	i = zg->zg_free;
	ZSTATS_INCX(zgc_zone_scans);

	while (i < zg->zg_zones) {
		struct subzinfo *szi = &zg->zg_subzinfo[i];

		/*
		 * If we have less that a subzone worth of free blocks, we no longer
		 * need to scan all the zones.
		 */

		if (zone->zn_blocks - zone->zn_cnt < zone->zn_hint)
			goto finished;

		/*
		 * If we have already freed enough subzones in the GC run, abort.
		 */

		if (zgc_context.subzone_freed >= ZGC_SUBZONE_FREEMAX) {
			if (zalloc_debugging(3)) {
				s_debug("ZGC %zu-byte zone %p: hit subzone free limit, "
					"will resume scanning at next run",
					zone->zn_size, (void *) zone);
			}
			must_continue = TRUE;
			break;
		}

		if (szi->szi_free_cnt != zone->zn_hint)
			goto next;

		if (zgc_subzone_free(zone, szi)) {
			ZSTATS_INCX(zgc_scan_freed);
			continue;
		}

		must_continue = TRUE;		/* Did not free empty subzone */

		/* FALL THROUGH */

	next:
		i++;
	}

	if (!must_continue)
		goto finished;

	return;

finished:
	zg->zg_flags &= ~ZGC_SCAN_ALL;

	if (zalloc_debugging(4)) {
		s_debug("ZGC %zu-byte zone %p turned scan-all off: "
			"%u blocks, %u free (hint=%u, %u subzones)",
			zone->zn_size, (void *) zone,
			zone->zn_blocks, zone->zn_blocks - zone->zn_cnt, zone->zn_hint,
			zone->zn_subzones);
	}
}

/**
 * Dispose of the garbage collecting structure.
 */
static void
zgc_dispose(zone_t *zone)
{
	unsigned free_blocks;
	struct zone_gc *zg;

	g_assert(zone->zn_cnt <= zone->zn_blocks);
	g_assert(zone->zn_gc != NULL);
	g_assert(zone->zn_free == NULL);
	g_assert(spinlock_is_held(&zone->lock));

	free_blocks = zone->zn_blocks - zone->zn_cnt;
	zg = zone->zn_gc;

	if (zalloc_debugging(1)) {
		time_delta_t elapsed = delta_time(tm_time(), zg->zg_start);
		s_debug("ZGC %zu-byte zone %p ending garbage collection "
			"(%u free block%s, %u subzone%s, freed %u and defragmented %u "
			"in %s)",
			zone->zn_size, (void *) zone,
			free_blocks, plural(free_blocks),
			zone->zn_subzones, plural(zone->zn_subzones),
			zg->zg_zone_freed, zg->zg_zone_defragmented,
			compact_time(elapsed));
	}

	/*
	 * If there are free blocks available, they must be put back to the
	 * main free list.  To help possible further garbage collection on the
	 * zone, we re-insert them in reverse order, keeping the subzone blocks
	 * together.
	 */

	if (free_blocks > 0) {
		unsigned i;
		unsigned max = zg->zg_zones;
		struct subzinfo *szi;
		unsigned dispatched = 0;

		for (i = 0, szi = &zg->zg_subzinfo[max - 1]; i < max; i++, szi--) {
			char **blk;

			while ((blk = szi->szi_free)) {
				szi->szi_free = (char **) *blk;		/* Remove block */
				*blk = (char *) zone->zn_free;		/* Insert before old head */
				zone->zn_free = blk;				/* New head */
				dispatched++;
			}
		}

		g_assert(dispatched == free_blocks);
	}

	/*
	 * Dispose the GC structures.
	 */

	xfree(zg->zg_subzinfo);
	xfree(zg);
	zone->zn_gc = NULL;			/* Back to regular zalloc() */
	atomic_uint_dec(&zgc_zone_cnt);

	g_assert(uint_is_non_negative(atomic_uint_get(&zgc_zone_cnt)));
}

/**
 * Allocate a block from the first subzone with free items.
 */
static void * G_HOT
zgc_zalloc(zone_t *zone)
{
	struct zone_gc *zg = zone->zn_gc;
	unsigned i;
	struct subzinfo *szi;
	char **blk;

	g_assert(spinlock_is_held(&zone->lock));

	ZSTATS_INCX(allocations_gc);

	/*
	 * Lookup for free blocks in each subzone, scanning them from the first
	 * one known to have free blocks and moving up.  By attempting to
	 * allocate from zones at the bottom of the array first, we keep the
	 * newest blocks in the lowest zones, possibly freeing up the zones
	 * at a higher place in memory, up to the point where they can be
	 * reclaimed.
	 */

	g_assert(uint_is_non_negative(zg->zg_free) && zg->zg_free < zg->zg_zones);

	if (addr_grows_upwards) {
		unsigned max = zg->zg_zones;

		for (i = zg->zg_free, szi = &zg->zg_subzinfo[i]; i < max; i++, szi++) {
			blk = szi->szi_free;
			if (blk != NULL)
				goto found;
			zg->zg_free = (i + 1 == max) ? zg->zg_free : i + 1;
		}
	} else {
		for (
			i = zg->zg_free, szi = &zg->zg_subzinfo[i];
			uint_is_non_negative(i);
			i--, szi--
		) {
			blk = szi->szi_free;
			if (blk != NULL)
				goto found;
			zg->zg_free = (i == 0) ? zg->zg_free : i - 1;
		}
	}

	/*
	 * No more free blocks, need a new zone.
	 *
	 * This means we can end trying to garbage-collect this zone unless we
	 * are requested to always GC the zones.
	 */

	g_assert(zone->zn_blocks == zone->zn_cnt);

	if (zgc_always(zone)) {
		blk = zgc_extend(zone);
	} else {
		zgc_dispose(zone);
		zg = NULL;
		blk = zn_extend(zone);			/* First block from new subzone */
		zone->zn_free = (char **) *blk;
	}

	goto extended;

found:
	g_assert(zgc_within_subzone(szi, blk));

	szi->szi_free = (char **) *blk;
	szi->szi_free_cnt--;

	g_assert(0 == szi->szi_free_cnt || zgc_within_subzone(szi, szi->szi_free));
	g_assert((0 == szi->szi_free_cnt) == (NULL == szi->szi_free));
	safety_assert(zgc_subzinfo_valid(zone, szi));

	/* FALL THROUGH */
extended:
	zone->zn_cnt++;
	zunlock(zone);
	return zprepare(zone, blk);
}

/**
 * Free block, returning it to the proper subzone free list.
 */
static void
zgc_zfree(zone_t *zone, void *ptr)
{
	g_assert(spinlock_is_held(&zone->lock));

	ZSTATS_INCX(freeings_gc);
	zone->zn_cnt--;
	zgc_insert_freelist(zone, ptr);
}

/**
 * Move block in the same zone to an hopefully better place.
 * @return new location for block.
 */
static void *
zgc_zmove(zone_t *zone, void *p)
{
	struct zone_gc *zg;
	struct subzinfo *szi, *nszi;
	unsigned i;
	char **blk;
	void *np;
	void *start;

	ZSTATS_INCX(zmove_attempts_gc);
	zlock(zone);

	zg = zone->zn_gc;

	g_assert(zg != NULL);

	szi = zgc_find_subzone(zg, p, NULL);

	g_assert(szi != NULL);
	g_assert(zgc_within_subzone(szi, p));
	g_assert((0 == szi->szi_free_cnt) == (NULL == szi->szi_free));
	g_assert(szi->szi_free_cnt < zone->zn_hint);	/* Has 1+ allocated blocks */
	safety_assert(zgc_subzinfo_valid(zone, szi));


	/*
	 * If block is the only one allocated in its subzone, then we have an
	 * opportunity to "defragment" by moving the whole zone and then move the
	 * data to the first block.
	 * 		--RAM, 2017-11-27
	 */

	if G_UNLIKELY(zone->zn_hint - 1 == szi->szi_free_cnt) {
		char *nbase;

		ZSTATS_INCX(zmove_1_block_in_subzone);

		nbase = vmm_core_move(szi->szi_base, szi->szi_sz->sz_size);

		if (nbase != szi->szi_base) {
			size_t offset;
			void *second_blk;

			/*
			 * Let's move the data to the first block in the new arena,
			 * if not already the first block, and then let's rebuild
			 * a free list with the remaining block, and update the
			 * subzone information.
			 */

			start = ptr_add_offset(p, -OVH_LENGTH);		/* Real block start */
			offset = ptr_diff(start, szi->szi_base);	/* In old arena */

			g_assert(offset < szi->szi_sz->sz_size);
			g_assert(size_is_non_negative(offset));

			np = ptr_add_offset(nbase, OVH_LENGTH);		/* Skip block overhead */

			if G_LIKELY(offset != 0) {
				/* Keep original meta info */
				memcpy(nbase, nbase + offset, zone->zn_size);
			}

			/*
			 * Rebuild free list for new arena address, skipping the first
			 * block of the new arena where we moved the data.
			 */

			second_blk = nbase + zone->zn_size;
			zn_cram(zone, second_blk, szi->szi_sz->sz_size - zone->zn_size);

			g_assert(szi->szi_free != NULL);			/* Old value */

			szi->szi_free = (char **) second_blk;
			zgc_subzone_moved(zone, szi, nbase);		/* Update subzone info */

			ZSTATS_INCX(zmove_successful_subzone);
			goto done;
		}

		/* FALL THROUGH */
	}

	if G_UNLIKELY(zone->zn_blocks == zone->zn_cnt)
		goto no_change;		/* No free blocks at all */

	if G_UNLIKELY(zone->zn_blocks - zone->zn_cnt == szi->szi_free_cnt)
		goto no_change;		/* No free blocks in any other subzone */

	/*
	 * Look for the "earliest" (in the VM space) subzone with a free block.
	 */

	i = szi - zg->zg_subzinfo;

	if (addr_grows_upwards) {
		unsigned j = zg->zg_free;		/* Lowest zone with free blocks */

		for (nszi = &zg->zg_subzinfo[j]; j < i; j++, nszi++) {
			blk = nszi->szi_free;
			if (blk != NULL)
				goto found;
		}
	} else {
		unsigned j = zg->zg_free;		/* Highest zone with free blocks */

		for (nszi = &zg->zg_subzinfo[j]; j > i; j--, nszi--) {
			blk = nszi->szi_free;
			if (blk != NULL)
				goto found;
		}
	}

	goto no_change;				/* Did not find any better zone */

	/*
	 * Found a subzone with free blocks "earlier" in the VM space.
	 * Move the block there.
	 */

found:

	ZSTATS_INCX(zmove_successful_gc);

	/*
	 * Remove block from the subzone's free list.
	 */

	g_assert(uint_is_positive(nszi->szi_free_cnt));
	g_assert(zgc_within_subzone(nszi, blk));

	nszi->szi_free = (char **) *blk;
	nszi->szi_free_cnt--;

	g_assert(!nszi->szi_free_cnt || zgc_within_subzone(nszi, nszi->szi_free));
	g_assert((0 == nszi->szi_free_cnt) == (NULL == nszi->szi_free));
	safety_assert(zgc_subzinfo_valid(zone, nszi));

	/*
	 * Also copy possible overhead (which is already included in the zone's
	 * block size).
	 */

	start = ptr_add_offset(p, -OVH_LENGTH);
	np = ptr_add_offset(blk, OVH_LENGTH);	/* Allow for block overhead */
	memcpy(blk, start, zone->zn_size);		/* Keep original meta info */

	if (zalloc_debugging(1)) {
		size_t used = zone->zn_hint - szi->szi_free_cnt - 1;
		s_debug("ZGC %zu-byte zone %p: moved %p to %p, "
			"zone has %u blocks, %u used (hint=%u, %u subzone%s), previous "
			"subzone has %zu block%s",
			zone->zn_size, (void *) zone, p, np,
			zone->zn_blocks, zone->zn_cnt, zone->zn_hint,
			zone->zn_subzones, plural(zone->zn_subzones),
			used, plural(used));
	}

#if defined(TRACK_ZALLOC) || defined(MALLOC_FRAMES)
	/*
	 * Since we moved the physical block around, update any non-leaking
	 * information we had on the old address, and if there is a shift
	 * between the allocated address and the used pointer, update it as
	 * well based on the new physical address.
	 */

	if (not_leaking != NULL) {
		void *a = NULL;
		void *b;
		size_t offset;

		ZLEAK_LOCK;

		if (alloc_real_to_used != NULL) {
			a = hash_table_lookup(alloc_real_to_used, p);
		}
		b = a != NULL ? a : p;
		g_assert(ptr_cmp(b, p) >= 0);
		offset = ptr_diff(b, p);
		if (hash_table_lookup(not_leaking, b) != NULL) {
			hash_table_remove(not_leaking, b);
			hash_table_insert(not_leaking, ptr_add_offset(np, offset),
				GINT_TO_POINTER(1));
		}
		if (a != NULL) {
			hash_table_remove(alloc_real_to_used, p);
			hash_table_remove(alloc_used_to_real, a);
			zalloc_shift_pointer(np, ptr_add_offset(np, offset));
		}

		ZLEAK_UNLOCK;
	}
#endif	/* TRACK_MALLOC || MALLOC_FRAMES */

	/*
	 * Put old block back into its subzone, which may result in it being
	 * freed up if it became empty (that's why we're moving blocks around).
	 */

	zgc_insert_freelist(zone, start);

done:
	zunlock(zone);
	return np;

no_change:
	zunlock(zone);
	return p;
}

/**
 * Add memory usage monitoring to zone.
 */
static void
zn_memusage_init(zone_t *zone)
{
	memusage_t *mu;

	/*
	 * Allocate the memusage object before locking the zone in case
	 * the creation of the object re-enters zalloc() for that same zone.
	 */

	mu = memusage_alloc("zone", zone->zn_size);

	zlock(zone);
	if (NULL == zone->zn_mem) {
		zone->zn_mem = mu;
		memusage_add_batch(mu, zone->zn_cnt);
		zunlock(zone);
	} else {
		zunlock(zone);
		memusage_free_null(&mu);
		g_assert(memusage_is_valid(zone->zn_mem));
	}
}

/**
 * Identify oversized zones.
 */
static void
spot_oversized_zone(zone_t *zone)
{
	if (!zlock_try(zone))
		return;

	g_assert(uint_is_positive(zone->zn_refcnt));
	g_assert(zone->zn_cnt <= zone->zn_blocks);

	/*
	 * It's not possible to create this object at zn_create() time because
	 * there is a danger of deadlocking from walloc() when the size of
	 * the objects to create matches the zone we're attempting to allocate.
	 */

	if G_UNLIKELY(NULL == zone->zn_mem && zalloc_memusage_ok) {
		zunlock(zone);
		zn_memusage_init(zone);
		zlock(zone);
	}

	/*
	 * A zone is oversized if it contains more than 1 subzone and if it has
	 * at least "1.5 hint" blocks free (i.e. with potentially extra subzones
	 * that could be released).
	 *
	 * However, to account for demand variability, we wait for at least
	 * ZN_OVERSIZE_THRESH times before flagging the zone as definitively
	 * oversized and candidate for stricter free block management, when we
	 * have less than "4 hints" blocks free.
	 *
	 * As soon as we have "4 hints" blocks free, we unconditionally trigger
	 * garbage collection mode.
	 */

	if (
		NULL == zone->zn_gc &&
		zone->zn_subzones > 1 &&
		zone->zn_blocks - zone->zn_cnt >= (zone->zn_hint + zone->zn_hint / 2)
	) {
		if (
			++zone->zn_oversized >= ZN_OVERSIZE_THRESH ||
			zgc_always(zone) ||
			zone->zn_blocks - zone->zn_cnt >= (4 * zone->zn_hint)
		) {
			if (zalloc_debugging(4)) {
				s_debug("ZGC %zu-byte zone %p %s: "
					"%u blocks, %u used (hint=%u, %u subzones)",
					zone->zn_size, (void *) zone,
					zgc_always(zone) ? "forced in GC mode" : "oversized",
					zone->zn_blocks, zone->zn_cnt, zone->zn_hint,
					zone->zn_subzones);
			}

			/*
			 * If zone holds no blocks, we can shrink it.
			 * Otherwise set it up for garbage collection.
			 */

			if (0 == zone->zn_cnt) {
				zn_shrink(zone);
			} else {
				zgc_allocate(zone);
				if (1 == zone->zn_subzones && !zgc_always(zone))
					zgc_dispose(zone);
			}

			if (zalloc_debugging(4)) {
				s_debug("ZGC %zu-byte zone %p %s: "
					"%u blocks, %u used (hint=%u, %u subzone%s)",
					zone->zn_size, (void *) zone,
					NULL == zone->zn_gc ? "after shrinking" : "has GC on",
					zone->zn_blocks, zone->zn_cnt, zone->zn_hint,
					zone->zn_subzones, plural(zone->zn_subzones));
			}
		}
	} else if (zgc_always(zone)) {
		if (NULL == zone->zn_gc) {
			if (zalloc_debugging(4)) {
				s_debug("ZGC %zu-byte zone %p forced in GC mode: "
					"%u blocks, %u used (hint=%u, %u subzones)",
					zone->zn_size, (void *) zone,
					zone->zn_blocks, zone->zn_cnt, zone->zn_hint,
					zone->zn_subzones);
			}
			zgc_allocate(zone);
		} else if (zone->zn_gc->zg_flags & ZGC_SCAN_ALL) {
			zgc_scan(zone);
		}
	} else {
		if (zone->zn_gc != NULL && (zone->zn_gc->zg_flags & ZGC_SCAN_ALL)) {
			zgc_scan(zone);
		}
		zone->zn_oversized = 0;
	}

	zunlock(zone);
}

/**
 * Zone garbage collector.
 *
 * This routine needs to be called periodically (preferably when the process is
 * rather idle) to incrementally monitor zones and clean up the oversized ones.
 * Typically, this routine is invoked from an idle callout queue timer.
 */
void
zgc(bool overloaded)
{
	tm_t start;
	size_t i, count;
	zone_t **zones;

	/*
	 * Garbage collecting only makes sense if we're going to be a long-running
	 * process -- for short-lived processes, it is an overkill.
	 */

	if (NULL == zt || !vmm_is_long_term())
		return;

	ZSTATS_INCX(zgc_runs);

	if (zalloc_debugging(0))
		tm_now_exact(&start);

	if (zalloc_debugging(3)) {
		s_debug("ZGC iterating over %u zones (%u in GC mode)",
			(unsigned) hash_table_count(zt), atomic_uint_get(&zgc_zone_cnt));
	}

	zgc_context.subzone_freed = overloaded ? ZGC_SUBZONE_OVERBASE : 0;

	/*
	 * Because spot_oversized_zone() can allocate memeory, we cannot iterate
	 * over the hash table in case it would be modified during the iteration.
	 * Linearize it first.
	 */

	zgc_context.running = TRUE;

	zones = (zone_t **) hash_table_values(zt, &count);

	for (i = 0; i < count; i++) {
		spot_oversized_zone(zones[i]);
	}
	xfree(zones);

	zgc_context.running = FALSE;

	if (zalloc_debugging(0)) {
		tm_t end;
		tm_now_exact(&end);
		s_debug("ZGC iterated over %u zones (%u in GC mode) in %u usecs",
			(unsigned) hash_table_count(zt), atomic_uint_get(&zgc_zone_cnt),
			(unsigned) tm_elapsed_us(&end, &start));
	}
}
#endif	/* !REMAP_ZALLOC */

/**
 * Called when the main callout queue is idle to run zgc().
 */
static bool
zalloc_idle_collect(void *unused_data)
{
	(void) unused_data;

	zgc(FALSE);
	return TRUE;		/* Keep calling */
}

/**
 * Install the periodic idle zgc() call.
 */
static void G_COLD
zalloc_zgc_install(void)
{
	evq_raw_idle_add(zalloc_idle_collect, NULL);
}

/**
 * Called when the VMM layer has been initialized.
 */
void G_COLD
zalloc_long_term(void)
{
	static once_flag_t zalloc_zgc_installed;

	/*
	 * We wait for the VMM layer to be up before we install the zgc() idle
	 * callback in an attempt to tweak the self-bootstrapping path.
	 *
	 * The GC is now only installed then vmm_set_strategy() is called to
	 * install a long-term allocation strategy.  Hence we know that the VMM
	 * layer is up.
	 *		--RAM, 2015-12-02
	 */

	once_flag_run(&zalloc_zgc_installed, zalloc_zgc_install);
}

/**
 * Initialize the zone allocator, once.
 */
static void G_COLD
zinit_once(void)
{
	addr_grows_upwards = vmm_grows_upwards();
#ifdef TRACK_ZALLOC
	z_leakset = leak_init();
#endif
}

/**
 * Initialize zone allocator.
 */
void G_COLD
zinit(void)
{
	static once_flag_t initialized;

	ONCE_FLAG_RUN(initialized, zinit_once);
}

/**
 * Turn on dynamic memory usage stats collection.
 */
void G_COLD
zalloc_memusage_init(void)
{
	zone_t **zones;
	size_t i, count;

	zalloc_memusage_ok = TRUE;

	if (NULL == zt)
		return;

	/*
	 * Can't iterate on the "zt" hash table directly because our process of
	 * setting up memory usage can allocate memory through zalloc() which
	 * may insert a new zone in the "zt" hash table.
	 *
	 * So get an array with all the known zones so far, then iterate over
	 * the array.  The array is allocated with xpmalloc() to prevent any
	 * memory allocation through zalloc().
	 */

	zones = (zone_t **) hash_table_values(zt, &count);

	for (i = 0; i < count; i++) {
		zone_t *zn = zones[i];

		zone_check(zn);

		if (NULL == zn->zn_mem) {
			zn_memusage_init(zn);
		} else {
			g_assert(memusage_is_valid(zn->zn_mem));
		}
	}

	xfree(zones);
}

/**
 * Turn off dynamic memory usage stats collection.
 */
void G_COLD
zalloc_memusage_close(void)
{
	zone_t **zones;
	size_t i, count;

	zalloc_memusage_ok = FALSE;

	if (NULL == zt)
		return;

	zones = (zone_t **) hash_table_values(zt, &count);

	for (i = 0; i < count; i++) {
		zone_t *zn = zones[i];
		memusage_t *mu = zn->zn_mem;

		zone_check(zn);

		/*
		 * Careful here, since freeing the memusage object can call zfree()
		 * and we don't want to renter zfree() with a lock on the zone as
		 * that would deadlock us.
		 */

		if (mu != NULL) {
			zlock(zn);
			g_assert(zn->zn_mem == mu);
			zn->zn_mem = NULL;
			zunlock(zn);
			memusage_free_null(&mu);
		}
	}

	xfree(zones);
}

/**
 * Control stackframe collection for a zone of given size.
 *
 * @param size		zone size
 *
 * @return TRUE if OK, FALSE if we found no zone with specified size.
 */
bool
zalloc_stack_accounting_ctrl(size_t size, enum zalloc_stack_ctrl op, ...)
{
	zone_t *zone;
	unsigned hint = 0;
	bool ok = TRUE;
	va_list args;
	zone_t key;

	if (NULL == zt)
		return FALSE;

	size = zalloc_adjust_size(size, &hint, FALSE);

	key.zn_size = size;
	key.private = FALSE;
	key.zn_stid = 0;

	zone = hash_table_lookup(zt, &key);

	if (NULL == zone)
		return FALSE;

	zone_check(zone);

	if (NULL == zone->zn_mem)
		return FALSE;

	va_start(args, op);

	switch (op) {
	case ZALLOC_SA_SET:
		{
			bool on = va_arg(args, bool);
			memusage_set_stack_accounting(zone->zn_mem, on);
			goto done;
		}
		return TRUE;
	case ZALLOC_SA_SHOW:
		{
			logagent_t *la = va_arg(args, logagent_t *);
			memusage_frame_dump_log(zone->zn_mem, la);
			goto done;
		}
	case ZALLOC_SA_MAX:
		break;
	}

	ok = FALSE;

done:
	va_end(args);
	return ok;
}

struct zonesize {
	size_t size;
	zone_t *zone;
};

/**
 * xsort() callback for sorting zonesize items by increasing size.
 */
static int
zonesize_cmp(const void *p1, const void *p2)
{
	const struct zonesize *zs1 = p1, *zs2 = p2;

	return CMP(zs1->size, zs2->size);
}

struct zonesize_filler {
	struct zonesize *array;
	size_t capacity;
	size_t count;
};

/**
 * Hash table iterator -- fill all known zones in an array for sorting.
 */
static void
zalloc_filler_add(const void *u_key, void *value, void *data)
{
	struct zonesize_filler *filler = data;
	zone_t *zone = value;
	struct zonesize *zs;

	(void) u_key;

	zone_check(zone);
	g_assert(filler->count < filler->capacity);

	zs = &filler->array[filler->count++];
	zs->size = zone->zn_size;
	zs->zone = zone;
}

/**
 * Construct sorted array of zones.
 */
static void
zalloc_sort_zones(struct zonesize_filler *fill)
{
	size_t zcount;

	g_assert(zt != NULL);

	/*
	 * We want to avoid calling xpmalloc() here, but since xmalloc() can
	 * call walloc() which can create a new zone, we have to be careful.
	 *
	 * Soon enough the call to walloc() will not create a new zone anyway,
	 * and in case the malloc freelist is depleted, using xmalloc() can
	 * avoid creating new core.
	 */

	hash_table_lock(zt);
	zcount = hash_table_count(zt);
	XMALLOC_ARRAY(fill->array, zcount);
	while (hash_table_count(zt) != zcount) {
		zcount = hash_table_count(zt);
		XREALLOC_ARRAY(fill->array, zcount);
	}
	fill->capacity = zcount;
	fill->count = 0;

	/*
	 * Safe to iterate, the callback zalloc_filler_add() does not allocate
	 * any memory so there cannot be any alteration to the "zt" hash.
	 */

	hash_table_foreach(zt, zalloc_filler_add, fill);
	hash_table_unlock(zt);

	g_assert(fill->count == fill->capacity);

	xqsort(fill->array, fill->count, sizeof fill->array[0], zonesize_cmp);
}

/**
 * Generate a SHA1 digest of the current zalloc statistics.
 *
 * This is meant for dynamic entropy collection.
 */
void
zalloc_stats_digest(sha1_t *digest)
{
	uint32 n = entropy_nonce();

	/*
	 * Don't take locks to read the statistics, to enhance unpredictability.
	 */

	ZSTATS_INCX(zalloc_stats_digest);
	SHA1_COMPUTE_NONCE(zstats, &n, digest);
}

/**
 * Dump zone status to specified log agent.
 */
void G_COLD
zalloc_dump_zones_log(logagent_t *la)
{
	struct zonesize_filler filler;
	size_t i, zpages, blocks, subzones;
	size_t bytes, wasted, overhead;

	if (NULL == zt)
		return;

	zalloc_sort_zones(&filler);

	zpages = blocks = subzones = 0;
	bytes = wasted = overhead = 0;

	for (i = 0; i < filler.count; i++) {
		zone_t *zone = filler.array[i].zone;
		unsigned bcnt, over;
		size_t remain;
		char buf[16];

		bcnt = zone->zn_blocks - zone->zn_cnt;
		g_assert(uint_is_non_negative(bcnt));

		blocks += bcnt;
		bytes += size_saturate_mult(bcnt, zone->zn_size);
		remain = zone->zn_arena.sz_size % zone->zn_size;
		wasted += size_saturate_mult(zone->zn_subzones, remain);
		subzones += zone->zn_subzones;
		zpages += vmm_page_count(zone->zn_arena.sz_size) * zone->zn_subzones;

		over = sizeof(*zone) + (zone->zn_subzones - 1) * sizeof(zone->zn_arena);
		if (zone->zn_gc != NULL) {
			struct zone_gc *zg = zone->zn_gc;
			over += sizeof(*zg);
			over += zg->zg_zones * sizeof(zg->zg_subzinfo[0]);
		}
		overhead += over;

		if (zone->private) {
			str_bprintf(buf, sizeof buf, ", stid=%u", zone->zn_stid);
		} else {
			buf[0] = 0;
		}

		log_info(la, "ZALLOC zone(%zu bytes%s): "
			"blocks=%u, free=%u, %u %zuK-subzone%s, over=%u, %s mode",
			zone->zn_size, buf, zone->zn_blocks, bcnt, zone->zn_subzones,
			zone->zn_arena.sz_size / 1024,
			plural(zone->zn_subzones), over,
			zone->zn_gc != NULL ? "GC" : "normal");
	}

	overhead += hash_table_memory(zt);

	log_info(la, "ZALLOC zones have %zu bytes (%s) free among %zu block%s",
		bytes, short_size(bytes, FALSE), blocks, plural(blocks));

	log_info(la, "ZALLOC zones wasting %zu bytes (%s) among %zu subzone%s "
		"(%zu page%s)",
		wasted, short_size(wasted, FALSE),
		subzones, plural(subzones), zpages, plural(zpages));

	log_info(la, "ZALLOC zones structural overhead totals %zu bytes (%s)",
		overhead, short_size(overhead, FALSE));

	xfree(filler.array);
}

/**
 * Dump zalloc() usage stats about zones to specified log agent.
 */
void G_COLD
zalloc_dump_usage_log(logagent_t *la, unsigned options)
{
	struct zonesize_filler filler;
	size_t i;

	if (NULL == zt)
		return;

	zalloc_sort_zones(&filler);

	for (i = 0; i < filler.count; i++) {
		zone_t *zone = filler.array[i].zone;

		if (NULL == zone->zn_mem) {
			log_warning(la,
				"zone(%zu bytes): memory usage stats not configured",
				zone->zn_size);
		} else {
			memusage_summary_dump_log(zone->zn_mem, la, options);
		}
	}

	xfree(filler.array);
}

/**
 * Dump zalloc() statistics to specified log agent.
 */
void G_COLD
zalloc_dump_stats_log(logagent_t *la, unsigned options)
{
	struct zstats stats;
	bool groupped = booleanize(options & DUMP_OPT_PRETTY);

	/* Will be always less than a thousand, ignore pretty-priting */
	log_info(la, "ZALLOC zone_count = %s",
		size_t_to_string(NULL == zt ? 0 : hash_table_count(zt)));

	ZSTATS_LOCK;
	stats = zstats;			/* struct copy under lock protection */
	ZSTATS_UNLOCK;

#define DUMP(x)	log_info(la, "ZALLOC %s = %s", #x,		\
	uint64_to_string_grp(stats.x, groupped))

#define DUMP64(x) G_STMT_START {							\
	uint64 v = AU64_VALUE(&zstats.x);						\
	log_info(la, "ZALLOC %s = %s", #x,						\
		uint64_to_string_grp(v, groupped));					\
} G_STMT_END

	DUMP(allocations);
	DUMP(freeings);
	DUMP(freeings_list);
	DUMP(freeings_list_blocks);
	DUMP64(allocations_gc);
	DUMP64(freeings_gc);
	DUMP(subzones_allocated);
	DUMP(subzones_allocated_pages);
	DUMP(subzones_freed);
	DUMP(subzones_freed_pages);
	DUMP64(zmove_attempts);
	DUMP64(zmove_attempts_gc);
	DUMP64(zmove_1_block_in_subzone);
	DUMP64(zmove_successful_gc);
	DUMP64(zmove_successful_smart);
	DUMP64(zmove_successful_subzone);
	DUMP64(zgc_zones_freed);
	DUMP64(zgc_zones_defragmented);
	DUMP64(zgc_fragments_freed);
	DUMP64(zgc_free_quota_reached);
	DUMP64(zgc_last_zone_kept);
	DUMP64(zgc_runs);
	DUMP64(zgc_zone_scans);
	DUMP64(zgc_scan_freed);
	DUMP(zgc_excess_zones_freed);
	DUMP(zgc_shrinked);

	/* Will be always less than a thousand, ignore pretty-priting */
	log_info(la, "ZALLOC zgc_zone_count = %u", atomic_uint_get(&zgc_zone_cnt));

#undef DUMP
#define DUMP(x)	log_info(la, "ZALLOC %s = %s", #x,		\
	(options & DUMP_OPT_PRETTY) ?						\
		size_t_to_gstring(stats.x) : size_t_to_string(stats.x))

	DUMP(user_memory);
	DUMP(user_blocks);

	DUMP64(zalloc_stats_digest);

#undef DUMP
#undef DUMP64
}

/**
 * Dump zalloc() statistics.
 */
void G_COLD
zalloc_dump_stats(void)
{
	s_info("ZALLOC running statistics:");
	zalloc_dump_stats_log(log_agent_stderr_get(), 0);
	s_info("ZALLOC zones status:");
	zalloc_dump_zones_log(log_agent_stderr_get());
}

/* vi: set ts=4 sw=4 cindent: */
