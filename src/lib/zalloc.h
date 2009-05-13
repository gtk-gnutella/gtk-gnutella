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

#ifndef _zalloc_h_
#define _zalloc_h_

#include "common.h" 

#define ZALLOC_ALIGNBYTES	MEM_ALIGNBYTES

/*
 * Object size rounding.
 */
#define ZALLOC_MASK	(ZALLOC_ALIGNBYTES - 1)
#define zalloc_round(s) \
	((gulong) (((gulong) (s) + ZALLOC_MASK) & ~ZALLOC_MASK))

struct zone;
typedef struct zone zone_t;

/*
 * Memory allocation routines.
 */

zone_t *zcreate(size_t, unsigned);
zone_t *zget(size_t, unsigned);
void zdestroy(zone_t *zone);

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

gpointer zalloc(zone_t *);
void zfree(zone_t *, gpointer);
void zclose(void);
void zgc(void);

void set_zalloc_debug(guint32 level);

#ifdef TRACK_ZALLOC

#define zalloc(z)	zalloc_track(z, _WHERE_, __LINE__)

gpointer zalloc_track(zone_t *z, char *file, int line);

#endif	/* TRACK_ZALLOC */

#endif /* _zalloc_h_ */

