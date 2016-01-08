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
 * Explicit-width block allocator, based on zalloc().
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _walloc_h_
#define _walloc_h_

#include "common.h"

#include "eslist.h"
#include "malloc.h"
#include "pslist.h"

/**
 * Maximum size for a walloc().  Anything larger is allocated by using
 * either halloc() or xpmalloc().
 */
#define WALLOC_MAX_SHIFT	13	/* 2^13 = 8192 bytes */
#define WALLOC_MAX			(1 << WALLOC_MAX_SHIFT)

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

#define walloc(s)			g_malloc(s)
#define walloc0(s)			g_malloc0(s)

static inline void *
wcopy(const void *p, size_t size)
{
	return g_memdup(p, size);
}

static inline void
wfree(void *p, size_t size)
{
	(void) size;
	g_free(p);
}

static inline void
wfree_pslist(pslist_t *pl, size_t size)
{
	pslist_t *next, *l;

	(void) size;

	for (l = pl; l != NULL; l = next) {
		next = l->next;
		g_free(l);
	}
}

static inline void
wfree_eslist(eslist_t *el, size_t size)
{
	void *next, *p;

	(void) size;

	for (p = eslist_head(el); p != NULL; p = next) {
		next = eslist_next_data(el, p);
		g_free(p);
	}
}

static inline void
wfree0(void *p, size_t size)
{
	memset(p, 0, size);
	g_free(p);
}

static inline void *
wrealloc(void *p, size_t o, size_t n)
{
	(void) o;
	return g_realloc(p, n);
}

static inline void *
wmove(void *p, size_t n)
{
	(void) n;
	return p;
}

#else	/* !REMAP_ZALLOC */

void *walloc(size_t size) G_MALLOC;
void *walloc0(size_t size) G_MALLOC;
void wfree(void *ptr, size_t size);
void wfree0(void *ptr, size_t size);
void *wrealloc(void *old, size_t old_size, size_t new_size) G_MALLOC;
void *wmove(void *ptr, size_t size) WARN_UNUSED_RESULT;
void wfree_pslist(pslist_t *pl, size_t size);
void wfree_eslist(eslist_t *el, size_t size);

/* Don't define both an inline routine and a macro... */
#ifndef TRACK_ZALLOC
static inline void *wcopy(const void *ptr, size_t size) G_MALLOC;

static inline void *
wcopy(const void *ptr, size_t size)
{
	void *cp = walloc(size);
	memcpy(cp, ptr, size);
	return cp;
}
#endif

#endif	/* REMAP_ZALLOC */

#ifdef TRACK_ZALLOC

#define walloc(s)			walloc_track(s, _WHERE_, __LINE__)
#define wcopy(p,s)			wcopy_track(p, s, _WHERE_, __LINE__)
#define walloc0(s)			walloc0_track(s, _WHERE_, __LINE__)
#define wrealloc(p,o,n)		wrealloc_track(p, o, n, _WHERE_, __LINE__)

void *walloc_track(size_t size, const char *file, int line);
void *walloc0_track(size_t size, const char *file, int line);
void *wcopy_track(const void *, size_t size, const char *file, int line);
void *wrealloc_track(void *old, size_t old_size, size_t new_size,
	const char *file, int line);

#endif	/* TRACK_ZALLOC */

void walloc_init(void);
void walloc_crash_mode(void);
size_t walloc_active_limit(void);
size_t walloc_size_threshold(void);
void wdestroy(void);

size_t walloc_maxsize(void) G_GNUC_CONST;

#define WALLOC(p)			\
G_STMT_START {				\
	p = walloc(sizeof *p);	\
} G_STMT_END

#define WALLOC0(p)			\
G_STMT_START {				\
	p = walloc0(sizeof *p);	\
} G_STMT_END

#define WMOVE(p)			wmove(p, sizeof *p)
#define WCOPY(p)			wcopy(p, sizeof *p)

#define WFREE(p)			\
G_STMT_START {				\
	wfree(p, sizeof *p);	\
} G_STMT_END

#define WFREE0(p)			\
G_STMT_START {				\
	wfree0(p, sizeof *p);	\
} G_STMT_END

#define WFREE_TYPE_NULL(p)	\
G_STMT_START {				\
	if (p) {				\
		wfree(p, sizeof *p);\
		p = NULL;			\
	}						\
} G_STMT_END

#define WFREE_NULL(p,size)	\
G_STMT_START {				\
	if (p) {				\
		wfree(p, size);		\
		p = NULL;			\
	}						\
} G_STMT_END

#define WALLOC_ARRAY(p,n)			\
G_STMT_START {						\
	p = walloc((n) * sizeof p[0]);	\
} G_STMT_END

#define WALLOC0_ARRAY(p,n)				\
G_STMT_START {							\
	p = walloc0((n) * sizeof p[0]);		\
} G_STMT_END

#define WFREE_ARRAY(p,n)			\
G_STMT_START {						\
	wfree(p, (n) * sizeof p[0]);	\
} G_STMT_END

#define WFREE_ARRAY_NULL(p,n)			\
G_STMT_START {							\
	if (p) {							\
		wfree(p, (n) * sizeof p[0]);	\
		p = NULL;						\
	}									\
} G_STMT_END

#define WREALLOC_ARRAY(p,n,m)								\
G_STMT_START {												\
	p = wrealloc(p, (n) * sizeof p[0], (m) * sizeof p[0]);	\
} G_STMT_END

#define WCOPY_ARRAY(p,n)	wcopy(p, (n) * sizeof p[0])

#endif /* _walloc_h_ */

/* vi: set ts=4 sw=4 cindent: */
