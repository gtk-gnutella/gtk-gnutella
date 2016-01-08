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
 * Under TRACK_ZALLOC we remap halloc() and halloc0() in case these routines
 * perform their allocation through zalloc().
 */

#if defined(TRACK_ZALLOC) && !defined(TRACK_MALLOC)
#define halloc(_s)	halloc_track(_s, _WHERE_, __LINE__)
#define halloc0(_s)	halloc0_track(_s, _WHERE_, __LINE__)

void *halloc_track(size_t size,
	const char *file, int line) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void *halloc0_track(size_t size,
	const char *file, int line) WARN_UNUSED_RESULT G_GNUC_MALLOC;
#else
#ifndef TRACK_MALLOC
void *halloc(size_t size) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void *halloc0(size_t size) WARN_UNUSED_RESULT G_GNUC_MALLOC;
#endif
#endif	/* TRACK_ZALLOC */

/*
 * Under TRACK_MALLOC control, these routines are remapped to malloc()/free().
 */

#ifndef TRACK_MALLOC
void hfree(void *ptr);
void *hrealloc(void *old, size_t size) WARN_UNUSED_RESULT;

static inline void * WARN_UNUSED_RESULT G_GNUC_MALLOC
hcopy(const void *p, size_t size)
{
	void *cp = halloc(size);
	memcpy(cp, p, size);
	return cp;
}

char *h_strdup(const char *str) WARN_UNUSED_RESULT G_GNUC_MALLOC;
char *h_strndup(const char *str, size_t n) WARN_UNUSED_RESULT G_GNUC_MALLOC;
char *h_strjoinv(const char *separator, char * const *str_ary);
char *h_strnjoinv(const char *separator, size_t seplen, char * const *str_ary);
void h_strfreev(char **str_array);
char *h_strconcat(const char *str1, ...) WARN_UNUSED_RESULT G_GNUC_MALLOC 
	G_NULL_TERMINATED;
char *h_strconcat_v(const char *first, va_list ap)
	WARN_UNUSED_RESULT G_GNUC_MALLOC;
char *h_strdup_printf(const char *format, ...) G_GNUC_PRINTF(1, 2);
char *h_strdup_vprintf(const char *format, va_list ap) G_GNUC_PRINTF(1, 0);
char *h_strdup_len_vprintf(const char *format, va_list ap, size_t *len)
	G_GNUC_PRINTF(1, 0);
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

void *h_private(const void *key, void *p);

struct logagent;
struct sha1;

void halloc_dump_stats_log(struct logagent *la, unsigned options);
void halloc_stats_digest(struct sha1 *digest);

#ifdef TRACK_MALLOC

#define HFREE_NULL(p)	\
G_STMT_START {			\
	if (p) {			\
		free_track((p), _WHERE_, __LINE__); \
		p = NULL;		\
	}					\
} G_STMT_END

#else	/* !TRACK_MALLOC */

#define HFREE_NULL(p)	\
G_STMT_START {			\
	if (p) {			\
		hfree(p);		\
		p = NULL;		\
	}					\
} G_STMT_END

#endif	/* TRACK_MALLOC */

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
