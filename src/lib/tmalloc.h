/*
 * Copyright (c) 2013 Raphael Manfredi
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
 * Thread Magazine allocator.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _tmalloc_h_
#define _tmalloc_h_

typedef struct tmalloc_depot tmalloc_t;

enum tmalloc_info_magic { TMALLOC_INFO_MAGIC = 0x7e60619b };

/**
 * Allocator information that can be retrieved.
 */
typedef struct {
	enum tmalloc_info_magic magic;
	const char *name;				/**< Allocator's name (read-only) */
	size_t size;					/**< Object size */
	size_t attached;				/**< Threads currently using allocator */
	size_t magazines;				/**< Magazines handed out to threads */
	size_t mag_capacity;			/**< Current magazine capacity */
	size_t mag_full;				/**< Amount of full magazines in depot */
	size_t mag_empty;				/**< Amount of empty magazines in depot */
	size_t mag_full_trash;			/**< Full magazines, trashed */
	size_t mag_empty_trash;			/**< Empty magazines, trashed */
	size_t mag_object_trash;		/**< Objects in the trash */
	uint64 allocations;				/**< Total amount of object allocations */
	uint64 allocations_zeroed;		/**< Allocations zeroed */
	uint64 depot_allocations;		/**< Allocations made via the depot layer */
	uint64 depot_trashings;			/**< Objects trashed to depot by tmfree() */
	uint64 freeings;				/**< Amount of object freeings */
	uint64 freeings_list;			/**< Amount of object freeings via list */
	uint64 freeings_list_count;		/**< Total objects freed via list */
	uint64 threads;					/**< Total amount of threads attached */
	uint64 contentions;				/**< Total amount of lock contentions */
	uint64 preemptions;				/**< Signal handler preemptions seen */
	uint64 object_trash_reused;		/**< Amount of trashed objects reused */
	uint64 empty_trash_reused;		/**< Empty trashed magazines reused */
	uint64 capacity_increased;		/**< Magazine capacity increases */
	uint64 mag_allocated;			/**< Total amount of magazines allocated */
	uint64 mag_freed;				/**< Total amount of magazines freed */
	uint64 mag_trashed;				/**< Total amount of magazines trashed */
	uint64 mag_unloaded;			/**< Total amount of magazines unloaded */
	uint64 mag_empty_trashed;		/**< Empty magazines trashed */
	uint64 mag_empty_freed;			/**< Empty magazines freed */
	uint64 mag_empty_loaded;		/**< Empty magazines loaded */
	uint64 mag_full_rebuilt;		/**< Full magazines rebuilt from trash */
	uint64 mag_full_trashed;		/**< Full magazines trashed */
	uint64 mag_full_freed;			/**< Full magazines freed */
	uint64 mag_full_loaded;			/**< Full magazines loaded */
	uint64 mag_used_freed;			/**< Partially filled magazines freed */
	uint64 mag_bad_capacity;		/**< Magazines freed due to bad capacity */
} tmalloc_info_t;

static inline void
tmalloc_info_check(const tmalloc_info_t * const tmi)
{
	g_assert(tmi != NULL);
	g_assert(TMALLOC_INFO_MAGIC == tmi->magic);
}

/*
 * Public interface.
 */

void set_tmalloc_debug(uint32 level);

tmalloc_t *tmalloc_create(const char *name, size_t size,
	alloc_fn_t allocate, free_size_fn_t deallocate);
void tmalloc_reset(tmalloc_t *tma);
size_t tmalloc_size(const tmalloc_t *tma);

struct pslist;
struct eslist;

void *tmalloc(tmalloc_t *tma) G_MALLOC;
void *tmalloc0(tmalloc_t *tma) G_MALLOC;
void tmfree(tmalloc_t *tma, void *p);
void tmfree_pslist(tmalloc_t *tma, struct pslist *pl);
void tmfree_eslist(tmalloc_t *tma, struct eslist *el);

struct logagent;
struct sha1;

void tmalloc_stats_digest(struct sha1 *digest);

struct pslist *tmalloc_info_list(void);
void tmalloc_info_list_free_null(struct pslist **sl_ptr);
void tmalloc_dump_stats_log(struct logagent *la, unsigned options);
void tmalloc_dump_magazines_log(struct logagent *la);
void tmalloc_dump_stats(void);

#endif /* _tmalloc_h_ */

/* vi: set ts=4 sw=4 cindent: */
