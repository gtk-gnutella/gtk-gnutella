/*
 * $Id$
 *
 * Copyright (c) 2002-2003, 2009 Raphael Manfredi
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
 * @author Raphael Manfredi
 * @date 2002-2003
 * @date 2009
 */

#include "common.h"

RCSID("$Id$")

#include "zalloc.h"
#include "hashtable.h"
#include "misc.h"
#include "tm.h"

#include "override.h"		/* Must be the last header included */

#define equiv(p,q)		(!(p) == !(q))

/**
 * Extra allocated zones.
 */
struct subzone {
	struct subzone *sz_next;	/**< Next allocated zone chunk, NULL if last */
	gpointer sz_base;			/**< Base address of zone arena */
	size_t sz_size;				/**< Size of zone arena */
	time_t sz_ctime;			/**< Creation time */
};

/**
 * Subzone information for garbage collection.
 */
struct subzinfo {
	gpointer szi_base;			/**< Base zone arena address (convenience) */
	gpointer szi_end;			/**< Pointer to first byte after arena */
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
	unsigned zg_zones;				/**< Amount of zones in zg_subzinfo[] */
	unsigned zg_free;				/**< First subzinfo with free blocks */
	guint32 zg_flags;				/**< GC flags */
};

/**
 * Zone GC flags
 */
#define ZGC_SCAN_ALL	(1 << 0)	/**< Scan all subzones at next run */

/**
 * Global zone garbage collector state.
 */
static struct {
	unsigned subzone_freed;			/**< Amount of subzones freed this run */
	gboolean running;				/**< Garbage collector is running */
} zgc_context;

#define ZGC_SUBZONE_MINLIFE		5	/**< Do not free too recent subzone */
#define ZGC_SUBZONE_FREEMAX		64	/**< Max # of subzones freed in a run */
#define ZGC_SUBZONE_OVERBASE	48	/**< Initial base when CPU overloaded */

/**
 * @struct zone
 *
 * Zone structure.
 *
 * Zone structures can be linked together to form one big happy chain.
 * During allocation/free, only the first zone structure of the list is
 * updated. The other subzone structures are updated only during the garbage
 * collecting phase, if any.
 */

struct zone {				/* Zone descriptor */
    struct subzone zn_arena;
	struct zone_gc *zn_gc;	/**< Optional: garbage collecting information */
	char **zn_free;			/**< Pointer to first free block */
	size_t zn_size;			/**< Size of blocks in zone */
	unsigned zn_refcnt;		/**< How many references to that zone? */
	unsigned zn_hint;		/**< Hint size, for next zone extension */
	unsigned zn_cnt;		/**< Amount of used blocks in zone */
	unsigned zn_blocks;		/**< Total amount of blocks in zone */
	unsigned zn_subzones;	/**< Amount of subzones */
	unsigned zn_oversized;	/**< For GC: amount of times we see oversizing */
};

static hash_table_t *zt;			/**< Keeps size (rounded up) -> zone */
static guint32 zalloc_debug;		/**< Debug level */
static gboolean zalloc_always_gc;	/**< Whether zones should stay in GC mode */
static unsigned zgc_zone_cnt;		/**< Zones in garbage collecting mode */

/*
 * Define ZONE_SAFE to allow detection of duplicate frees on a zone object.
 *
 * Don't leave that as the default because it adds an overhead to each allocated
 * block, which defeats one of the advantages of having a zone allocation in
 * the first place!
 */
#if (defined(DMALLOC) || defined(TRACK_ZALLOC)) && !defined(ZONE_SAFE)
#define ZONE_SAFE
#endif

#ifdef ZONE_SAFE
#define SAFE_REV_OFFSET		(2 * sizeof(char *))
#else
#define SAFE_REV_OFFSET		0
#endif

#ifdef TRACK_ZALLOC

#undef zalloc				/* We want the real zalloc() routine here */

#define FILE_REV_OFFSET		(sizeof(char *) + sizeof(int))

#else	/* !TRACK_ZALLOC */
#define FILE_REV_OFFSET		0
#endif	/* TRACK_ZALLOC */

#define USED_REV_OFFSET		(SAFE_REV_OFFSET + FILE_REV_OFFSET)

#ifdef ZONE_SAFE
#define BLOCK_USED			((char *) 0xff12aa35)	/**< Tag for used blocks */
#endif

#define DEFAULT_HINT		8		/**< Default amount of blocks in a zone */
#define MAX_ZONE_SIZE		32768	/**< Maximum zone size */

/* Under REMAP_ZALLOC, map zalloc() and zfree() to g_malloc() and g_free() */

#ifdef REMAP_ZALLOC
gpointer
zalloc(zone_t *zone)
{
	return g_malloc(zone->zn_size);
}

void
zfree(zone_t *zone, gpointer ptr)
{
	(void) zone;
	g_free(ptr);
}

#else	/* !REMAP_ZALLOC */

static char **zn_extend(zone_t *);
static gpointer zgc_zalloc(zone_t *);
static void zgc_zfree(zone_t *, gpointer);
static void zgc_allocate(zone_t *zone);
static void zgc_dispose(zone_t *);

/**
 * Return block, with possible size adjustment for tracking and markup,
 * as determined by compile options.
 */
static inline gpointer
zprepare(zone_t *zone, char **blk)
{
	(void) zone;
#ifdef ZONE_SAFE
	*blk++ = BLOCK_USED;
	*blk++ = (char *) zone;
#endif
#ifdef TRACK_ZALLOC
	blk = (char **) ((char *) blk + FILE_REV_OFFSET);
#endif
	return blk;
}

/**
 * Allcate memory with fixed size blocks (zone allocation).
 *
 * Returns a pointer to a block containing at least 'size' bytes of
 * memory.  It is a fatal error if memory cannot be allocated.
 *
 * A zone is, in its simplest expression, a memory chunk where fix-sized
 * blocks are sliced, all free blocks being chained together via a link
 * written in the first bytes of the block. To allocate a block, the first
 * free block is removed from the list. Freeing is just as easy, since we
 * insert the block at the head of the free list.
 *
 * Zone chunks are linked together to make a bigger pool, where only the
 * first zone descriptor is accurate (i.e. only it has meaningful zn_cnt and
 * zn_free fields).
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
 */
gpointer
zalloc(zone_t *zone)
{
	char **blk;		/**< Allocated block */

	/* NB: this routine must be as fast as possible. No assertions */

	/*
	 * Grab first available free block and update free list pointer. If we
	 * succeed in getting a block, we are done so return immediately.
	 */

	blk = zone->zn_free;
	if (blk != NULL) {
		zone->zn_free = (char **) *blk;
		zone->zn_cnt++;
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

	if (zone->zn_gc != NULL)
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

	return zprepare(zone, blk);
}

#ifdef TRACK_ZALLOC
/**
 * Tracking version of zalloc().
 */
gpointer
zalloc_track(zone_t *zone, char *file, int line)
{
	char *blk = zalloc(zone);
	char *p;

	p = blk - FILE_REV_OFFSET;			/* Go backwards */
	*(char **) p = short_filename(file);
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
zblock_log(char *p, int size, gpointer leakset)
{
	char *uptr;			/* User pointer */
	char *file;
	int line;

	uptr = p + sizeof(char *);		/* Skip used marker */
	file = *(char **) uptr;
	uptr += sizeof(char *);
	line = *(int *) uptr;
	uptr += sizeof(int);

	g_warning("leaked block 0x%lx from \"%s:%d\"", (gulong) uptr, file, line);

	leak_add(leakset, size, file, line);
}

/**
 * Go through the whole zone and dump all the used blocks.
 */
static void
zdump_used(zone_t *zone)
{
	int used = 0;
	struct subzone *sz;
	char *p;
	gpointer leakset = leak_init();

	for (sz = &zone->zn_arena; sz; sz = sz->sz_next) {
		char *end;

		p = sz->sz_base;
		end = p + sz->sz_size;

		while (p < end) {
			if (*(char **) p == BLOCK_USED) {
				used++;
				zblock_log(p, zone->zn_size, leakset);
			}
			p += zone->zn_size;
		}
	}

	if (used != zone->zn_cnt) {
		g_warning("BUG: "
			"found %d used block%s, but %d-byte zone said it was holding %d",
			used, 1 == used ? "" : "s", zone->zn_size, zone->zn_cnt);
	}

	leak_dump(leakset);
	leak_close(leakset);
}
#endif	/* TRACK_ZALLOC */

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
zfree(zone_t *zone, gpointer ptr)
{
	char **head;
	g_assert(ptr);
	g_assert(zone);

#ifdef ZONE_SAFE
	{
		char **tmp;

		/* Go back at leading magic, also the start of the block */
		tmp = (char **) ((char *) ptr - USED_REV_OFFSET);

		if (tmp[0] != BLOCK_USED)
			g_error("trying to free block 0x%lx twice", (gulong) ptr);
		if (tmp[1] != (char *) zone)
			g_error("trying to free block 0x%lx to wrong zone", (gulong) ptr);
		ptr = tmp;
	}
#endif

	g_assert(uint_is_positive(zone->zn_cnt)); 	/* Has something to free! */

	head = zone->zn_free;

	if (NULL == head && NULL != zone->zn_gc) {
		zgc_zfree(zone, ptr);
	} else {
		*(char **) ptr = (char *) head;			/* Will precede old head */
		zone->zn_free = ptr;					/* New free list head */
		zone->zn_cnt--;							/* To make zone gc easier */
	}
}
#endif	/* !REMAP_ZALLOC */

/**
 * Cram a new zone in chunk.
 *
 * A zone consists of linked blocks, where the address of the next free block
 * is written in the first bytes of each free block.
 */
static void
zn_cram(zone_t *zone, gpointer arena)
{
	unsigned i;
	char **next = arena, *p = arena;
	size_t size = zone->zn_size;
	unsigned hint = zone->zn_hint;

	for (i = 1; i < hint; i++) {
		next = (gpointer) p;
		p = *next = &p[size];
	}
	next = (gpointer) p;
	*next = NULL;
}

static void
subzone_alloc_arena(struct subzone *sz, size_t size)
{
	sz->sz_size = round_pagesize(size);
	sz->sz_base = vmm_alloc(sz->sz_size);
	sz->sz_ctime = tm_time();
}

static void
subzone_free_arena(struct subzone *sz)
{
	vmm_free(sz->sz_base, sz->sz_size);
	sz->sz_base = NULL;
	sz->sz_size = 0;
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
		free(sz);
		sz = next;
	}

	zone->zn_arena.sz_next = NULL;
}

/**
 * Adjust the block size so that we minimize the amount of wasted
 * memory per subzone chunk and get blocks large enough to store possible
 * extra information when debugging.
 *
 * @return adjusted block size and updated hint value
 */
static size_t
adjust_size(size_t requested, unsigned *hint_ptr)
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

	size += USED_REV_OFFSET;

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
			if (zalloc_debug) {
				g_message("ZALLOC adjusting block size from %u to %u "
					"(%u blocks will waste %u bytes at end of %u-byte subzone)",
					(unsigned) requested, (unsigned) adjusted, hint,
					(unsigned) (rounded - hint * adjusted), rounded);
			}
		} else {
			if (zalloc_debug) {
				g_message("ZALLOC cannot adjust block size of %u "
					"(%u blocks will waste %u bytes at end of %u-byte subzone)",
					(unsigned) requested, hint,
					(unsigned) (rounded - hint * adjusted), rounded);
			}
		}

		size = adjusted;
	}

	*hint_ptr = hint;
	return size;
}

/**
 * Create a new zone able to hold `hint' items of 'size' bytes.
 */
static zone_t *
zn_create(zone_t *zone, size_t size, unsigned hint)
{
	g_assert(size > 0);
	g_assert(uint_is_non_negative(hint));

	/*
	 * Allocate the arena.
	 */

	subzone_alloc_arena(&zone->zn_arena, size * hint);

	/*
	 * Initialize zone descriptor.
	 */

	zone->zn_hint = hint;
	zone->zn_size = size;
	zone->zn_arena.sz_next = NULL;			/* Link keep track of arenas */
	zone->zn_cnt = 0;
	zone->zn_free = zone->zn_arena.sz_base;	/* First free block available */
	zone->zn_refcnt = 1;
	zone->zn_subzones = 1;					/* One subzone to start with */
	zone->zn_blocks = zone->zn_hint;
	zone->zn_gc = NULL;

	zn_cram(zone, zone->zn_arena.sz_base);

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

	sz = malloc(sizeof *sz);

	subzone_alloc_arena(sz, zone->zn_size * zone->zn_hint);

	if (NULL == sz->sz_base)
		g_error("cannot extend %u-byte zone", (unsigned) zone->zn_size);

	zone->zn_free = sz->sz_base;
	sz->sz_next = zone->zn_arena.sz_next;
	zone->zn_arena.sz_next = sz;		/* New subzone at head of list */
	zone->zn_subzones++;
	zone->zn_oversized = 0;				/* Just extended, cannot be oversized */
	zone->zn_blocks += zone->zn_hint;

	zn_cram(zone, sz->sz_base);

	return zone->zn_free;
}

/**
 * Shrink zone by discarding all subzones but the first.
 * Can only be called on zones with no allocated blocks.
 */
static void
zn_shrink(zone_t *zone)
{
	g_assert(0 == zone->zn_cnt);		/* No blocks used */

	if (zalloc_debug > 1) {
		g_message("ZGC %u-byte zone 0x%lx shrunk: "
			"freeing %u subzone%s of %uK (%u blocks each)",
			(unsigned) zone->zn_size, (unsigned long) zone,
			zone->zn_subzones - 1, 2 == zone->zn_subzones ? "" : "s",
			(unsigned) zone->zn_arena.sz_size / 1024, zone->zn_hint);
	}

	zn_free_additional_subzones(zone);
	zone->zn_subzones = 1;				/* One subzone remains */
	zone->zn_blocks = zone->zn_hint;
	zone->zn_free = zone->zn_arena.sz_base;	/* First free block available */
	zone->zn_oversized = 0;

	zn_cram(zone, zone->zn_arena.sz_base);	/* Recreate free list */
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
 */
zone_t *
zcreate(size_t size, unsigned hint)
{
	zone_t *zone;			/* Zone descriptor */

	zone = malloc(sizeof *zone);

	zn_create(zone, size, hint);

	if (zalloc_always_gc)
		zgc_allocate(zone);

	return zone;
}

/**
 * Destroy a zone chunk by releasing its memory to the system if possible,
 * converting it into a malloc chunk otherwise.
 */
void
zdestroy(zone_t *zone)
{
	/*
	 * A zone can be used by many different parts of the code, through
	 * calls to zget().  Therefore, only destroy the zone when all references
	 * are gone.
	 */

	g_assert(zone);
	g_assert(uint_is_positive(zone->zn_refcnt));

	if (zone->zn_refcnt-- > 1)
		return;

	if (zone->zn_cnt) {
		g_warning("destroyed zone (%d-byte blocks) still holds %d entr%s",
			zone->zn_size, zone->zn_cnt, zone->zn_cnt == 1 ? "y" : "ies");
#ifdef TRACK_ZALLOC
		zdump_used(zone);
#endif
	}

	if (zone->zn_gc)
		zgc_dispose(zone);

	zn_free_additional_subzones(zone);
	subzone_free_arena(&zone->zn_arena);
	hash_table_remove(zt, GINT_TO_POINTER(zone->zn_size));
	free(zone);
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
zget(size_t size, unsigned hint)
{
	zone_t *zone;

	/*
	 * Allocate hash table if not already done!
	 */

	if (zt == NULL)
		zt = hash_table_new();

	/*
	 * Adjust the requested size to ensure proper alignment of allocated
	 * memory blocks and minimize the amount of wasted space in subzones.
	 */

	size = adjust_size(size, &hint);

	zone = hash_table_lookup(zt, GINT_TO_POINTER(size));

	/*
	 * Supplied hint value is ignored if a zone already exists for that size
	 */

	if (zone) {
		zone->zn_refcnt++;
		return zone;				/* Found a zone for matching size! */
	}

	/*
	 * No zone of the corresponding size already, create a new one!
	 */

	zone = zcreate(size, hint);

	/*
	 * Insert new zone in the hash table so that we can return it to other
	 * clients requesting a similar size. If we can't insert it, it's not
	 * a fatal error, only a warning: we can always allocate a new zone next
	 * time!
	 */

	hash_table_insert(zt, GINT_TO_POINTER(size), zone);

	return zone;
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
		g_warning("zone (%d-byte blocks) still had %u references",
			zone->zn_size, zone->zn_refcnt);
		zone->zn_refcnt = 1;
	}

	zdestroy(zone);
}

/**
 * Close the zone allocator, destroying all the remaining zones regardless
 * of their reference count.
 */
void
zclose(void)
{
	if (NULL == zt)
		return;

	hash_table_foreach(zt, free_zone, NULL);
	hash_table_destroy(zt);
	zt = NULL;
}

/**
 * Set debug level.
 */
void
set_zalloc_debug(guint32 level)
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
set_zalloc_always_gc(gboolean val)
{
	zalloc_always_gc = val;
}

/***
 *** Garbage collector
 ***/

#define ZN_OVERSIZE_THRESH	90

/**
 * Compare two subzinfo based on base address -- qsort() callback.
 */
static int
subzinfo_cmp(const void *a, const void *b)
{
	const struct subzinfo *sa = a;
	const struct subzinfo *sb = b;

	g_assert(sa->szi_base != sb->szi_base);

	return sa->szi_base < sb->szi_base ? -1 : +1;
}

/**
 * Lookup subzone holding the block.
 */
static struct subzinfo *
zgc_find_subzone(struct zone_gc *zg, gpointer blk)
{
	struct subzinfo *array = zg->zg_subzinfo;
	unsigned low = 0;
	unsigned high = zg->zg_zones - 1;

	/* Binary search */

	while (low <= high && uint_is_non_negative(high)) {
		unsigned mid = low + (high - low) / 2;
		struct subzinfo *item;

		g_assert(mid < zg->zg_zones);

		item = &array[mid];
		if (blk >= item->szi_end)
			low = mid + 1;
		else if (blk < item->szi_base)
			high = mid - 1;
		else
			return item;
	}

	return NULL;	/* Not found */
}

/**
 * Free up a subzone which is completely empty.
 *
 * @return TRUE if OK, FALSE if we did not free it.
 */
static gboolean
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
	 * Also, to accomodate rapid zalloc()/zfree() usage patterns for a zone,
	 * do not release a subzone that was allocated too recently.
	 *
	 * This strategy imposes us to flag the zone as requiring a complete
	 * subzone scan at the next GC run because otherwise we could be left with
	 * many free zones after massive zfree() calls.  That scan will only
	 * happen if we have more free blocks in the zone than the amount of
	 * blocks held in a subzone, or it will be cancelled (since by definition
	 * we cannot have a free subzone when we have less than a subzone worth).
	 */

	if (1 == zone->zn_subzones)
		return FALSE;

	if (
		zone->zn_blocks - zone->zn_cnt <= zone->zn_hint ||
		delta_time(tm_time(), szi->szi_sz->sz_ctime) < ZGC_SUBZONE_MINLIFE
	) {
		zg->zg_flags |= ZGC_SCAN_ALL;
		return FALSE;
	}

	/*
	 * If we have already freed our quota of subzones during this GC cycle,
	 * do not free the zone.
	 */

	if (
		zgc_context.running &&
		zgc_context.subzone_freed >= ZGC_SUBZONE_FREEMAX
	) {
		if (zalloc_debug > 3) {
			g_message("ZGC %u-byte zone 0x%lx: hit subzone free limit",
				(unsigned) zone->zn_size, (unsigned long) zone);
		}
		zg->zg_flags |= ZGC_SCAN_ALL;
		return FALSE;
	}

	if (szi->szi_base == zone->zn_arena.sz_base) {

		g_assert(sz != NULL);	/* We know there are more than 1 subzone */

		if (zalloc_debug > 1) {
			unsigned free_blocks = zone->zn_blocks - zone->zn_cnt -
				zone->zn_hint;
			time_delta_t life = delta_time(tm_time(), zone->zn_arena.sz_ctime);
			g_message("ZGC %u-byte zone 0x%lx: freeing first subzone "
				"[0x%lx, 0x%lx] %uK, %u blocks, lifetime %s "
				"(still has %u free block%s)",
				(unsigned) zone->zn_size, (unsigned long) zone,
				(unsigned long) szi->szi_base,
				(unsigned long) szi->szi_end - 1,
				(unsigned) (szi->szi_end - szi->szi_base) / 1024,
				zone->zn_hint, compact_time(life),
				free_blocks, 1 == free_blocks ? "" : "s");
		}

		subzone_free_arena(&zone->zn_arena);
		zone->zn_arena = *sz;	/* Struct copy */
		free(sz);
	} else {
		unsigned n = 2;
		struct subzone *prev = &zone->zn_arena;

		while (sz) {
			struct subzone *next = sz->sz_next;

			if (sz->sz_base == szi->szi_base) {
				if (zalloc_debug > 1) {
					unsigned free_blocks = zone->zn_blocks - zone->zn_cnt -
						zone->zn_hint;
					time_delta_t life = delta_time(tm_time(), sz->sz_ctime);
					g_message("ZGC %u-byte zone 0x%lx: freeing subzone #%u "
						"[0x%lx, 0x%lx] %uK, %u blocks, lifetime %s "
						"(still has %u free block%s)",
						(unsigned) zone->zn_size, (unsigned long) zone, n,
						(unsigned long) szi->szi_base,
						(unsigned long) szi->szi_end - 1,
						(unsigned) (szi->szi_end - szi->szi_base) / 1024,
						zone->zn_hint, compact_time(life),
						free_blocks, 1 == free_blocks ? "" : "s");
				}
				subzone_free_arena(sz);
				free(sz);
				prev->sz_next = next;
				goto found;
			}

			prev = sz;
			sz = next;
			n++;
		}

		g_error("subzone to delete not found in list");
	}

found:

	zone->zn_blocks -= zone->zn_hint;
	zone->zn_subzones--;
	zgc_context.subzone_freed++;

	/*
	 * Remove subzone info from sorted array.
	 */

	zg->zg_zone_freed++;
	zg->zg_zones--;

	if (szi == &zg->zg_subzinfo[zg->zg_zones]) {
		/* Removing last zone */
		if (zg->zg_free == zg->zg_zones)
			zg->zg_free--;
	} else {
		unsigned i = szi - zg->zg_subzinfo;

		g_assert(uint_is_non_negative(i));
		g_assert(i < zg->zg_zones);

		memmove(&zg->zg_subzinfo[i], &zg->zg_subzinfo[i+1],
			(zg->zg_zones - i) * sizeof(struct subzinfo));

		if (zg->zg_free > i)
			zg->zg_free = i;
	}

	g_assert(uint_is_non_negative(zg->zg_free) && zg->zg_free < zg->zg_zones);

	return TRUE;
}

/**
 * Insert block into proper subzone's free list.
 * When the subzone is completely empty, free it.
 *
 * @return TRUE if block was inserted, FALSE if subzone was freed.
 */
static gboolean
zgc_insert_freelist(zone_t *zone, struct zone_gc *zg, char **blk)
{
	struct subzinfo *szi;
	unsigned idx;

	szi = zgc_find_subzone(zg, blk);
	g_assert(szi != NULL);
	g_assert(blk >= (char **) szi->szi_base && blk < (char **) szi->szi_end);

	/*
	 * Whether we are going to free up the subzone or not, we put the block
	 * back to the freelist.  Indeed, zgc_subzone_free() will never accept
	 * to free up the first subzone if it is the only one remaining, so we
	 * don't want to lose the freed block should the subzone be kept.
	 */

	*blk = (char *) szi->szi_free;		/* Precede old head */
	szi->szi_free = blk;

	/*
	 * Remember index of first subzinfo with free blocks to accelerate
	 * zgc_zalloc().
	 */

	idx = szi - zg->zg_subzinfo;

	g_assert(uint_is_non_negative(idx) && idx < zg->zg_zones);

	if (idx < zg->zg_free)
		zg->zg_free = idx;

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

	if (zalloc_debug > 1) {
		unsigned free_blocks = zone->zn_blocks - zone->zn_cnt;
		g_message("ZGC %u-byte zone 0x%lx: "
			"setting up garbage collection for %u subzone%s, %u free block%s",
			(unsigned) zone->zn_size, (unsigned long) zone,
			zone->zn_subzones, 1 == zone->zn_subzones ? "" : "s",
			free_blocks, 1 == free_blocks ? "" : "s");
	}

	zg = malloc(sizeof *zg);
	zone->zn_gc = zg;

	zg->zg_zones = zone->zn_subzones;
	zg->zg_subzinfo = malloc(zg->zg_zones * sizeof(struct subzinfo));
	zg->zg_zone_freed = 0;
	zg->zg_start = tm_time();
	zg->zg_free = 0;
	zg->zg_flags = 0;

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
	 */

	qsort(zg->zg_subzinfo, zg->zg_zones, sizeof *szi, subzinfo_cmp);

	/*
	 * Dispatch each free block to the proper subzone free list.
	 */

	while ((blk = zone->zn_free)) {
		zone->zn_free = (char **) *blk;
		dispatched++;
		if (!zgc_insert_freelist(zone, zg, blk)) {
			g_assert(dispatched >= zone->zn_hint);
			dispatched -= zone->zn_hint;	/* Subzone removed */
		}
	}

	zgc_zone_cnt++;

	g_assert(dispatched == zone->zn_blocks - zone->zn_cnt);
	g_assert(NULL == zone->zn_free);
	g_assert(zone->zn_gc != NULL);
}

/**
 * Extend garbage-collected zone.
 *
 * @return new free block, removed from free list.
 */
static gpointer
zgc_extend(zone_t *zone)
{
	char **blk;
	struct zone_gc *zg;
	struct subzone *sz;
	struct subzinfo *szi;
	struct subzinfo *array;
	unsigned low, high;
	char *start;
	char *end;

	g_assert(zone->zn_gc != NULL);
	g_assert(zone->zn_free == NULL);

	/*
	 * Extend the zone by allocating a new subzone.
	 */

	blk = zn_extend(zone);
	sz = zone->zn_arena.sz_next;		/* Allocated zone */

	g_assert(zone->zn_free != NULL);
	g_assert(blk == sz->sz_base);

	/*
	 * Find index at which we must insert the new zone in the sorted array.
	 */

	zg = zone->zn_gc;
	start = sz->sz_base;
	end = start + sz->sz_size;
	array = zg->zg_subzinfo;
	high = zg->zg_zones - 1;
	low = 0;

	while (low <= high && uint_is_non_negative(high)) {
		unsigned mid = low + (high - low) / 2;
		struct subzinfo *item;

		g_assert(mid < zg->zg_zones);

		item = &array[mid];
		if ((gpointer) blk >= item->szi_end)
			low = mid + 1;
		else if ((gpointer) blk < item->szi_base)
			high = mid - 1;
		else
			g_error("new subzone cannot be present in the array");
	}

	/*
	 * Insert new subzone at `low'.
	 */

	zg->zg_zones++;
	array = realloc(array, zg->zg_zones * sizeof(struct subzinfo));
	zg->zg_subzinfo = array;

	g_assert(uint_is_non_negative(low) && low < zg->zg_zones);

	if (low < zg->zg_zones - 1) {
		memmove(&array[low+1], &array[low],
			sizeof(struct subzinfo) * (zg->zg_zones - 1 - low));
	}

	szi = &array[low];
	szi->szi_base = start;
	szi->szi_end = end;
	szi->szi_free_cnt = zone->zn_hint - 1;	/* About to use first block */
	szi->szi_free = (char **) *blk;			/* Unchained from free list */
	szi->szi_sz = sz;

	zone->zn_free = NULL;		/* In GC mode, we never use this */
	zg->zg_free = low;			/* The subzone we have just added */

	if (zalloc_debug > 4) {
		g_message("ZGC %u-byte zone 0x%lx extended by "
			"%u blocks in [0x%lx, 0x%lx]",
			(unsigned) zone->zn_size, (unsigned long) zone,
			zone->zn_hint, (unsigned long) start, (unsigned long) end);
	}

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
	time_t now;
	gboolean must_continue = FALSE;

	g_assert(zg != NULL);
	g_assert(zone->zn_blocks >= zone->zn_cnt);

	if (zalloc_debug > 4) {
		g_message("ZGC %u-byte zone 0x%lx scanned for free subzones: "
			"%u blocks, %u free (hint=%u, %u subzones)",
			(unsigned) zone->zn_size, (unsigned long) zone,
			zone->zn_blocks, zone->zn_blocks - zone->zn_cnt, zone->zn_hint,
			zone->zn_subzones);
	}

	i = zg->zg_free;
	now = tm_time();

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
			if (zalloc_debug > 3) {
				g_message("ZGC %u-byte zone 0x%lx: hit subzone free limit, "
					"will resume scanning at next run",
					(unsigned) zone->zn_size, (unsigned long) zone);
			}
			must_continue = TRUE;
			break;
		}

		if (szi->szi_free_cnt != zone->zn_hint)
			goto next;

		if (zgc_subzone_free(zone, szi))
			continue;

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

	if (zalloc_debug > 4) {
		g_message("ZGC %u-byte zone 0x%lx turned scan-all off: "
			"%u blocks, %u free (hint=%u, %u subzones)",
			(unsigned) zone->zn_size, (unsigned long) zone,
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

	free_blocks = zone->zn_blocks - zone->zn_cnt;
	zg = zone->zn_gc;

	if (zalloc_debug > 1) {
		time_delta_t elapsed = delta_time(tm_time(), zg->zg_start);
		g_message("ZGC %u-byte zone 0x%lx ending garbage collection "
			"(%u free block%s, %u subzone%s, freed %u in %s)",
			(unsigned) zone->zn_size, (unsigned long) zone,
			free_blocks, 1 == free_blocks ? "" : "s",
			zone->zn_subzones, 1 == zone->zn_subzones ? "" : "s",
			zg->zg_zone_freed, compact_time(elapsed));
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

	free(zg->zg_subzinfo);
	free(zg);
	zone->zn_gc = NULL;			/* Back to regular zalloc() */
	zgc_zone_cnt--;

	g_assert(uint_is_non_negative(zgc_zone_cnt));
}

/**
 * Allocate a block from the first subzone with free items.
 */
static gpointer
zgc_zalloc(zone_t *zone)
{
	struct zone_gc *zg = zone->zn_gc;
	unsigned max = zg->zg_zones;
	unsigned i;
	struct subzinfo *szi;
	char **blk;


	for (i = zg->zg_free, szi = &zg->zg_subzinfo[i]; i < max; i++, szi++) {
		blk = szi->szi_free;

		if (NULL == blk) {
			zg->zg_free = (i + 1 == max) ? zg->zg_free : i + 1;
			continue;
		}

		szi->szi_free = (char **) *blk;
		szi->szi_free_cnt--;
		zone->zn_cnt++;
		return zprepare(zone, blk);
	}

	/*
	 * No more free blocks, need a new zone.
	 *
	 * This means we can end trying to garbage-collect this zone unless we
	 * are requested to always GC the zones.
	 */

	g_assert(zone->zn_blocks == zone->zn_cnt);

	if (zalloc_always_gc) {
		blk = zgc_extend(zone);
	} else {
		zgc_dispose(zone);
		blk = zn_extend(zone);				/* First block from new subzone */
		zone->zn_free = (char **) *blk;
	}

	zone->zn_cnt++;
	return zprepare(zone, blk);
}

/**
 * Free block, returning it to the proper subzone free list.
 */
static void
zgc_zfree(zone_t *zone, gpointer ptr)
{
	zone->zn_cnt--;
	zgc_insert_freelist(zone, zone->zn_gc, ptr);
}

/**
 * Hash table iterator to identify oversized zones.
 */
static void
spot_oversized_zone(const void *u_key, void *value, void *u_data)
{
	zone_t *zone = value;

	g_assert(uint_is_positive(zone->zn_refcnt));
	g_assert(zone->zn_cnt <= zone->zn_blocks);
	(void) u_key;
	(void) u_data;

	/*
	 * A zone is oversized if it contains more than 1 subzone and if it has
	 * at least "1.5 hint" blocks free (i.e. with potentially extra subzones
	 * that could be released).
	 *
	 * However, to account for demand variability, we wait for at least
	 * ZN_OVERSIZE_THRESH times before flagging the zone as definitively
	 * oversized and candidate for stricter free block management.
	 */

	if (
		NULL == zone->zn_gc &&
		zone->zn_subzones > 1 &&
		zone->zn_blocks - zone->zn_cnt >= (zone->zn_hint + zone->zn_hint / 2)
	) {
		if (++zone->zn_oversized >= ZN_OVERSIZE_THRESH || zalloc_always_gc) {
			if (zalloc_debug > 4) {
				g_message("ZGC %u-byte zone 0x%lx %s: "
					"%u blocks, %u used (hint=%u, %u subzones)",
					(unsigned) zone->zn_size, (unsigned long) zone,
					zalloc_always_gc ? "forced in GC mode" : "oversized",
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
				if (1 == zone->zn_subzones && !zalloc_always_gc)
					zgc_dispose(zone);
			}

			if (zalloc_debug > 4) {
				g_message("ZGC %u-byte zone 0x%lx %s: "
					"%u blocks, %u used (hint=%u, %u subzone%s)",
					(unsigned) zone->zn_size, (unsigned long) zone,
					NULL == zone->zn_gc ? "after shrinking" : "has GC on",
					zone->zn_blocks, zone->zn_cnt, zone->zn_hint,
					zone->zn_subzones, 1 == zone->zn_subzones ? "" : "s");
			}
		}
	} else if (zalloc_always_gc) {
		if (NULL == zone->zn_gc) {
			if (zalloc_debug > 4) {
				g_message("ZGC %u-byte zone 0x%lx forced in GC mode: "
					"%u blocks, %u used (hint=%u, %u subzones)",
					(unsigned) zone->zn_size, (unsigned long) zone,
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
}

/**
 * Zone garbage collector.
 *
 * This routine needs to be called periodically (preferably when the process is
 * rather idle) to incrementally monitor zones and clean up the oversized ones.
 * Typically, this routine is invoked from an idle callout queue timer.
 */
void
zgc(gboolean overloaded)
{
	static time_t last_run;
	time_t now;
	tm_t start;

	if (NULL == zt)
		return;

	/*
	 * Limit iterations to one per second.
	 */

	now = tm_time();
	if (last_run == now)
		return;
	last_run = now;

	if (zalloc_debug > 2)
		tm_now_exact(&start);

	if (zalloc_debug > 3) {
		g_message("ZGC iterating over %u zones (%u in GC mode)",
			(unsigned) hash_table_size(zt), zgc_zone_cnt);
	}

	zgc_context.subzone_freed = overloaded ? ZGC_SUBZONE_OVERBASE : 0;

	zgc_context.running = TRUE;
	hash_table_foreach(zt, spot_oversized_zone, NULL);
	zgc_context.running = FALSE;

	if (zalloc_debug > 2) {
		tm_t end;
		tm_now_exact(&end);
		g_message("ZGC iterated over %u zones (%u in GC mode) in %u usecs",
			(unsigned) hash_table_size(zt), zgc_zone_cnt,
			(unsigned) tm_elapsed_us(&end, &start));
	}
}

/* vi: set ts=4: */
