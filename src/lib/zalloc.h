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

#include <glib.h>

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

zone_t *zcreate(gint, gint);
zone_t *zget(gint, gint);
void zdestroy(zone_t *zone);

/*
 * Under REMAP_ZALLOC control, those routines are remapped to malloc/free.
 * Under TRACK_ZALLOC, we keep track of the allocation places.
 */

#if defined(USE_DMALLOC) && !defined(REMAP_ZALLOC)
#define REMAP_ZALLOC
#endif

#ifdef REMAP_ZALLOC

#ifdef TRACK_ZALLOC
#error "TRACK_ZALLOC and REMAP_ZALLOC are mutually exclusive"
#endif

#define zalloc(z)	g_malloc((z)->zn_size)
#define zfree(z,o)	g_free(o)

#else	/* !REMAP_ZALLOC */

gpointer zalloc(zone_t *);
void zfree(zone_t *, gpointer);

#endif	/* REMAP_ZALLOC */

#ifdef TRACK_ZALLOC

#define zalloc(z)	zalloc_track(z, __FILE__, __LINE__)

gpointer zalloc_track(zone_t *z, gchar *file, gint line);

#endif	/* TRACK_ZALLOC */

#endif /* _zalloc_h_ */

