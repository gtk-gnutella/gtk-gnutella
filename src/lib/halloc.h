/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
 * Under TRACK_ZALLOC we remap halloc() and halloc0() in case these routines
 * perform their allocation through zalloc().
 */

#if defined(TRACK_ZALLOC) && !defined(TRACK_MALLOC)
#define halloc(_s)	halloc_track(_s, _WHERE_, __LINE__)
#define halloc0(_s)	halloc0_track(_s, _WHERE_, __LINE__)

void *halloc_track(size_t size,
	const char *file, int line) G_MALLOC G_NON_NULL;
void *halloc0_track(size_t size,
	const char *file, int line) G_MALLOC G_NON_NULL;
#else
#ifndef TRACK_MALLOC
void *halloc(size_t size) G_MALLOC G_NON_NULL;
void *halloc0(size_t size) G_MALLOC G_NON_NULL;
#endif
#endif	/* TRACK_ZALLOC */

/*
 * Under TRACK_MALLOC control, these routines are remapped to malloc()/free().
 */

#ifndef TRACK_MALLOC
void hfree(void *ptr);
void *hrealloc(void *old, size_t size) G_NON_NULL WARN_UNUSED_RESULT;

static inline void * G_MALLOC G_NON_NULL
hcopy(const void *p, size_t size)
{
	void *cp = halloc(size);
	memcpy(cp, p, size);
	return cp;
}
#endif	/* !TRACK_MALLOC */

void halloc_init(bool replace_malloc);
bool halloc_disable(void);
bool halloc_is_disabled(void);
bool halloc_is_possible(void);
void hdestroy(void);
bool halloc_replaces_malloc(void);
bool halloc_is_available(void);

size_t halloc_bytes_allocated(void);
size_t halloc_chunks_allocated(void);

struct logagent;
struct sha1;

void halloc_dump_stats_log(struct logagent *la, unsigned options);
void halloc_stats_digest(struct sha1 *digest);

#define HFREE_NULL(p)	\
G_STMT_START {			\
	if (p) {			\
		hfree(p);		\
		p = NULL;		\
	}					\
} G_STMT_END

#define HALLOC_ARRAY(p,n)			\
G_STMT_START {						\
	p = halloc((n) * sizeof p[0]);	\
} G_STMT_END

#define HALLOC0_ARRAY(p,n)				\
G_STMT_START {							\
	p = halloc0((n) * sizeof p[0]);	\
} G_STMT_END

#define HREALLOC_ARRAY(p,n)				\
G_STMT_START {							\
	p = hrealloc(p, (n) * sizeof p[0]);	\
} G_STMT_END

#define HCOPY_ARRAY(p,n)	hcopy(p, (n) * sizeof p[0])

#endif /* _halloc_h_ */

/* vi: set ts=4 sw=4 cindent: */
