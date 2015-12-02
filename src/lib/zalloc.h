/*
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

#ifndef _zalloc_h_
#define _zalloc_h_

#include "common.h" 

#define ZALLOC_ALIGNBYTES	MEM_ALIGNBYTES

/*
 * Object size rounding.
 */
#define ZALLOC_MASK	(ZALLOC_ALIGNBYTES - 1)
#define zalloc_round(s) \
	((ulong) (((ulong) (s) + ZALLOC_MASK) & ~ZALLOC_MASK))

struct zone;
typedef struct zone zone_t;

/*
 * Memory allocation routines.
 */

zone_t *zcreate(size_t, unsigned, bool);
zone_t *zget(size_t, unsigned, bool);
void zdestroy(zone_t *zone);
bool zdestroy_if_empty(zone_t *zone);

size_t zone_blocksize(const zone_t *zone) G_GNUC_PURE;
size_t zone_size(const zone_t *zone) G_GNUC_PURE;
size_t zalloc_overhead(void) G_GNUC_CONST;

/*
 * Under REMAP_ZALLOC control, those routines are remapped to malloc/free.
 * Under TRACK_ZALLOC, we keep track of the allocation places.
 */

#if defined(USE_DMALLOC) && !defined(REMAP_ZALLOC)
#define REMAP_ZALLOC
#endif

#if defined(REMAP_ZALLOC) && defined(TRACK_ZALLOC)
#error "TRACK_ZALLOC and REMAP_ZALLOC are mutually exclusive"
#endif	/* REMAP_ZALLOC && TRACK_ZALLOC */

struct logagent;
struct pslist;
struct eslist;
struct sha1;

void *zalloc(zone_t *) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void zfree(zone_t *, void *);
void *zmove(zone_t *zone, void *p) WARN_UNUSED_RESULT;
void zfree_pslist(zone_t *, struct pslist *);
void zfree_eslist(zone_t *zone, struct eslist *el);
void zgc(bool overloaded);
void zalloc_long_term(void);

void zalloc_stats_digest(struct sha1 *digest);

void zinit(void);
void zclose(void);
void zalloc_vmm_inited(void);
void set_zalloc_debug(uint32 level);
void set_zalloc_always_gc(bool val);
void zalloc_memusage_init(void);
void zalloc_memusage_close(void);
void zalloc_dump_stats(void);
void zalloc_dump_usage_log(struct logagent *la, unsigned options);
void zalloc_dump_stats_log(struct logagent *la, unsigned options);
void zalloc_dump_zones_log(struct logagent *la);

enum zalloc_stack_ctrl {
	ZALLOC_SA_SET = 0,		/**< Turn stack accounting on/off */
	ZALLOC_SA_SHOW,			/**< Show statistics on specified logger */

	ZALLOC_SA_MAX
};

bool zalloc_stack_accounting_ctrl(size_t size, enum zalloc_stack_ctrl op, ...);

#ifdef TRACK_ZALLOC

#define zalloc(z)	zalloc_track(z, _WHERE_, __LINE__)

void *zalloc_track(zone_t *z, const char *file, int line);

#endif	/* TRACK_ZALLOC */

#if defined(TRACK_ZALLOC) || defined(MALLOC_STATS)
void zalloc_shift_pointer(const void *allocated, const void *used);
#endif

#endif /* _zalloc_h_ */

