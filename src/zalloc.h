/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Zone allocator.
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

#ifndef __zalloc_h__
#define __zalloc_h__

#include <glib.h>

#define ZALLOC_ALIGNBYTES	8		/* Would need metaconfig check */

/*
 * Object size rounding.
 */
#define ZALLOC_MASK	(ZALLOC_ALIGNBYTES - 1)
#define zalloc_round(s) \
	((gulong) (((gulong) (s) + ZALLOC_MASK) & ~ZALLOC_MASK))

/*
 * Zone structure.
 *
 * Zone structures can be linked together to form one big happy chain.
 * During allocation/free, only the first zone structure of the list is
 * updated. The other zone structures are updated only during the garbage
 * collecting phase, if any.
 */

struct subzone;

typedef struct zone {			/* Zone descriptor */
	gchar **zn_free;			/* Pointer to first free block */
	struct subzone *zn_next;	/* Next allocated zone chunk, null if none */
	gpointer zn_arena;			/* Base address of zone arena */
	gint zn_refcnt;				/* How many references to that zone? */
	gint zn_size;				/* Size of blocks in zone */
	gint zn_hint;				/* Hint size, for next zone extension */
	gint zn_cnt;				/* Amount of used blocks in zone */
} zone_t;

#define zcount(z)	((z)->zn_cnt)	/* Amount of allocated blocks */

/*
 * Memory allocation routines.
 */

zone_t *zcreate(gint, gint);
zone_t *zget(gint, gint);
void zdestroy(zone_t *zone);

/*
 * Under REMAP_ZALLOC control, those routines are remapped to malloc/free.
 */

#if defined(USE_DMALLOC) && !defined(REMAP_ZALLOC)
#define REMAP_ZALLOC
#endif

#ifdef REMAP_ZALLOC

#define zalloc(z)	g_malloc((z)->zn_size)
#define zfree(z,o)	g_free(o)

#else	/* !REMAP_ZALLOC */

gpointer zalloc(zone_t *);
void zfree(zone_t *, gpointer);

#endif	/* REMAP_ZALLOC */

#endif /* __zalloc_h__ */

