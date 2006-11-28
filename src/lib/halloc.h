/*
 * $Id$
 *
 * Copyright (c) 2006, Christian Biere
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
 * Hashtable-tracked allocator. Small chunks are allocated via walloc(),
 *
 * @author Christian Biere
 * @date 2006
 */

#ifndef _halloc_h_
#define _halloc_h_

#include "common.h"

/*
 * Under REMAP_ZALLOC control, those routines are remapped to malloc/free.
 */

#if defined(USE_DMALLOC) && !defined(REMAP_ZALLOC)
#define REMAP_ZALLOC
#endif

#ifdef REMAP_ZALLOC

static inline void halloc_init(void)	{ /* NOTHING */ }
static inline void hdestroy(void)		{ /* NOTHING */ }
static inline void *halloc(size_t n)	{ return g_malloc(n); }
static inline void *halloc0(size_t n)	{ return g_malloc0(n); }
static inline void hfree(void *p)		{ return g_free(p); }

static inline void *
hrealloc(void *p, size_t n)
{
	return g_realloc(p, n);
}

#else	/* !REMAP_ZALLOC */

void *halloc(size_t size) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void *halloc0(size_t size) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void hfree(void *ptr);
void *hrealloc(void *old, size_t size) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void halloc_init(void);
void hdestroy(void);

size_t halloc_bytes_allocated(void);
size_t halloc_chunks_allocated(void);
#endif	/* REMAP_ZALLOC */


#define HFREE_NULL(p)	\
G_STMT_START {			\
	if (p) {			\
		hfree(p);		\
		p = NULL;		\
	}					\
} G_STMT_END

#endif /* _halloc_h_ */
/* vi: set ts=4 sw=4 cindent: */
