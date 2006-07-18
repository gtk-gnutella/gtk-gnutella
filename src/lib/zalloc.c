/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 */

#include "common.h"

RCSID("$Id$");

#include "zalloc.h"
#include "override.h"		/* Must be the last header included */

/*
 * Define ZONE_SAFE to allow detection of duplicate frees on a zone object.
 *
 * Don't leave that as the default because it adds an overhead to each allocated
 * block, which defeats one of the advantages of having a zone allocation in
 * the first place!
 */
#if defined(DMALLOC) && !defined(ZONE_SAFE)
#define ZONE_SAFE
#endif

#ifdef ZONE_SAFE
#define FILE_REV_OFFSET		sizeof(gchar *)
#endif

#ifdef TRACK_ZALLOC

#undef zalloc				/* We want the real zalloc() routine here */

#ifndef ZONE_SAFE
#define ZONE_SAFE			/* Need used block tagging when tracking */
#endif

#define FILE_REV_OFFSET		(sizeof(gchar *) + sizeof(gint))
#undef USED_REV_OFFSET
#define USED_REV_OFFSET		(sizeof(gchar *) + FILE_REV_OFFSET)

#endif	/* TRACK_ZALLOC */

#ifdef ZONE_SAFE
#define BLOCK_USED			((gchar *) 0xff12aa35)	/**< Tagging of used blocks */
#endif

#define DEFAULT_HINT		128		/**< Default amount of blocks in a zone */
#define MAX_ZONE_SIZE		16384	/**< Maximum zone size */

/**
 * Extra allocated zones.
 */
struct subzone {
	struct subzone *zn_next;	/**< Next allocated zone chunk, null if last */
	gpointer zn_arena;			/**< Base address of zone arena */
};

static void zn_cram(zone_t *, gchar *, gint);
static struct zone *zn_create(zone_t *, gint, gint);

/* Under REMAP_ZALLOC, do not define zalloc() and zfree(). */

#ifndef REMAP_ZALLOC

static gchar **zn_extend(zone_t *);

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
	gchar **blk;		/**< Allocated block */

	/*
	 * Grab first available free block and update free list pointer. If we
	 * succeed in getting a block, we are done so return immediately.
	 */

	blk = zone->zn_free;
	if (blk != NULL) {
		zone->zn_free = (gchar **) *blk;
		zone->zn_cnt++;

#ifdef ZONE_SAFE
		*blk++ = BLOCK_USED;
#endif
#ifdef TRACK_ZALLOC
		blk = (gchar **) ((gchar *) blk + FILE_REV_OFFSET);
#endif

		return blk;
	}

	/*
	 * No more free blocks, extend the zone.
	 */

	blk = zn_extend(zone);
	if (blk == NULL)
		g_error("cannot extend zone to allocate a %d-byte block",
			zone->zn_size);

	/*
	 * Use first block from new extended zone.
	 */

	zone->zn_free = (char **) *blk;
	zone->zn_cnt++;

#ifdef ZONE_SAFE
	*blk++ = BLOCK_USED;
#endif
#ifdef TRACK_ZALLOC
	blk = (gchar **) ((gchar *) blk + FILE_REV_OFFSET);
#endif

	return blk;
}

#ifdef TRACK_ZALLOC
/**
 * Tracking version of zalloc().
 */
gpointer
zalloc_track(zone_t *zone, gchar *file, gint line)
{
	gchar *blk = zalloc(zone);
	gchar *p;

	p = blk - FILE_REV_OFFSET;			/* Go backwards */
	*(gchar **) p = file;
	p += sizeof(gchar *);
	*(gint *) p = line;

	return blk;
}

/**
 * Log information about block, `p' being the physical start of the block, not
 * the user part of it.  The block is known to be of size `size' and should
 * be also recorded in the `leakset' for summarizing of all the leaks.
 */
static void
zblock_log(gchar *p, gint size, gpointer leakset)
{
	gchar *uptr;			/* User pointer */
	gchar *file;
	gint line;

	uptr = p + sizeof(gchar *);		/* Skip used marker */
	file = *(gchar **) uptr;
	uptr += sizeof(gchar *);
	line = *(gint *) uptr;
	uptr += sizeof(gint);

	g_warning("leaked block 0x%lx from \"%s:%d\"", (gulong) uptr, file, line);

	leak_add(leakset, size, file, line);
}

/**
 * Go through the whole zone and dump all the used blocks.
 */
static void
zdump_used(zone_t *zone)
{
	gint used = 0;
	struct subzone *next;
	gchar *p;
	gpointer leakset = leak_init();

	p = (gchar *) zone->zn_arena;
	next = zone->zn_next;

	for (;;) {
		gint cnt = zone->zn_hint;		/* Amount of blocks per zone */

		while (cnt-- > 0) {
			if (*(gchar **) p == BLOCK_USED) {
				used++;
				zblock_log(p, zone->zn_size, leakset);
			}
			p += zone->zn_size;
		}

		if (next == NULL)
			break;

		p = (gchar *) next->zn_arena;
		next = next->zn_next;
	}

	if (used != zone->zn_cnt)
		g_warning("found %d used block, but zone said it was holding %d",
			used, zone->zn_cnt);

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
	g_assert(ptr);
	g_assert(zone);

#ifdef ZONE_SAFE
	{
		gchar **tmp;

		/* Go back at leading magic, also the start of the block */
		tmp = (gchar **) ((gchar *) ptr - USED_REV_OFFSET);

		if (*tmp != BLOCK_USED)
			g_error("trying to free block 0x%lx twice", (gulong) ptr);
		ptr = tmp;
	}
#endif

	g_assert(zone->zn_cnt > 0);		/* There must be something to free! */

	*(gchar **) ptr = (gchar *) zone->zn_free;	/* Will precede old head */
	zone->zn_free = (gchar **) ptr;				/* New free list head */
	zone->zn_cnt--;								/* To make zone gc easier */
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
zcreate(gint size, gint hint)
{
	zone_t *zone;			/* Zone descriptor */

	zone = g_malloc(sizeof(*zone));

	return zn_create(zone, size, hint);
}

/**
 * Create a new zone able to hold items of 'size' bytes.
 */
static zone_t *
zn_create(zone_t *zone, gint size, gint hint)
{
	gint asked;		/* Amount of bytes requested */
	gchar *arena;	/* Zone arena we got */

	/*
	 * Make sure size is big enough to store the free-list pointer used to
	 * chain all free blocks. Also round it so that all blocks are aligned on
	 * the correct boundary.
	 */

	g_assert(size > 0);
	if (size < (gint) sizeof(gchar *))
		size = sizeof(gchar *);

#ifdef ZONE_SAFE
	/*
	 * To secure the accesses, we reserve a pointer on top to make the linking.
	 * This pointer is filled in with the BLOCK_USED tag, enabling zfree to
	 * detect duplicate frees of a given block (which are indeed disastrous
	 * if done at all and the error remains undetected: the free list is
	 * corrupted).
	 */
	size += sizeof(gchar *);
#endif

#ifdef TRACK_ZALLOC
	/*
	 * When tracking allocation points, each block records the file and the
	 * line number where it was allocated from.
	 */
	size += sizeof(gchar *) + sizeof(gint);
#endif

	size = zalloc_round(size);

	g_assert(size < MAX_ZONE_SIZE);	/* Must not request zones for big sizes */

	/*
	 * Make sure we have at least room for `hint' blocks in the zone,
	 * and that at the same time, the size is not greater than MAX_ZONE_SIZE.
	 */

	hint = (hint == 0) ? DEFAULT_HINT : hint;
	asked = size * hint;

	if (asked > MAX_ZONE_SIZE) {
		hint = MAX_ZONE_SIZE / size;
		asked = size * hint;
	}

	g_assert(asked <= MAX_ZONE_SIZE);

	/*
	 * Allocate the arena.
	 */

	arena = g_malloc(asked);

	/*
	 * Initialize zone descriptor.
	 */

	zone->zn_hint = hint;
	zone->zn_size = size;
	zone->zn_next = NULL;			/* Link zones to keep track of arenas */
	zone->zn_cnt = 0;
	zone->zn_free = (gchar **) arena;	/* First free block available */
	zone->zn_arena = arena;				/* For GC, later on */
	zone->zn_refcnt = 1;

	zn_cram(zone, arena, size);

	return zone;
}

/**
 * Destroy a zone chunk by releasing its memory to the system if possible,
 * converting it into a malloc chunk otherwise.
 */
void
zdestroy(zone_t *zone)
{
	struct subzone *sz;
	struct subzone *next;

	/*
	 * A zone can be used by many different parts of the code, through
	 * calls to zget().  Therefore, only destroy the zone when all references
	 * are gone.
	 */

	g_assert(zone->zn_refcnt > 0);

	if (zone->zn_refcnt-- > 1)
		return;

	if (zone->zn_cnt) {
		g_warning("destroyed zone (%d-byte blocks) still holds %d entr%s",
			zone->zn_size, zone->zn_cnt, zone->zn_cnt == 1 ? "y" : "ies");
#ifdef TRACK_ZALLOC
		zdump_used(zone);
#endif
	}

	for (sz = zone->zn_next, next = NULL; sz; sz = next) {
		next = sz->zn_next;
		G_FREE_NULL(sz->zn_arena);
		g_free(sz);
	}

	G_FREE_NULL(zone->zn_arena);
	g_free(zone);
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
zget(gint size, gint hint)
{
	static GHashTable *zt;	/* Keeps size (modulo ZALLOC_ALIGNBYTES) -> zone */
	zone_t *zone;

	/*
	 * Allocate hash table if not already done!
	 */

	if (zt == NULL)
		zt = g_hash_table_new(NULL, NULL);

	/*
	 * Make sure size is big enough to store the free-list pointer used to
	 * chain all free blocks. Also round it so that all blocks are aligned on
	 * the correct boundary.
	 *
	 * This simply duplicates the adjustment done in zcreate. We have to do
	 * it now in order to allow proper lookup in the zone hash table.
	 */

	if (size < (gint) sizeof(gchar *))
		size = sizeof(gchar *);
	size = zalloc_round(size);

	zone = (zone_t *) g_hash_table_lookup(zt, GINT_TO_POINTER(size));

	if (zone) {
		if (zone->zn_hint < hint)
			zone->zn_hint = hint;	/* For further extension */
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

	g_hash_table_insert(zt, GINT_TO_POINTER(size), zone);

	return zone;
}

/**
 * Cram a new zone in chunk.
 *
 * A zone consists of linked blocks, where the address of the next free block
 * is written in the first bytes of each free block.
 */
static void
zn_cram(zone_t *zone, gchar *arena, gint size)
{
	gchar *end;		/* End address (first address beyond zone scope) */
	gchar *next;	/* Next free block in arena */

	end = arena + zone->zn_hint * zone->zn_size;

	for (next = arena + size; arena < end; next += size, arena += size)
		*(gchar **) arena = (next < end) ? next : (gchar *) 0;
}

#ifndef REMAP_ZALLOC
/**
 * Extend zone by allocating a new zone chunk.
 *
 * @return the address of the first new free block within the extended
 *         chunk arena.
 */
static gchar **
zn_extend(zone_t *zone)
{
	struct subzone *new;		/* New sub-zone */

	new = g_malloc(sizeof(*new));

	new->zn_arena = g_malloc(zone->zn_size * zone->zn_hint);
	zone->zn_free = (gchar **) new->zn_arena;

	new->zn_next = zone->zn_next;
	zone->zn_next = new;				/* New subzone at head of list */

	zn_cram(zone, new->zn_arena, zone->zn_size);

	return zone->zn_free;
}
#endif	/* !REMAP_ZALLOC */

/* vi: set ts=4: */
