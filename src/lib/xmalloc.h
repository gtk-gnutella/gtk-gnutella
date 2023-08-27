/*
 * Copyright (c) 2011 Raphael Manfredi
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
 * Memory allocator for replacing libc's malloc() and friends.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _xmalloc_h_
#define _xmalloc_h_

#include "common.h"

#ifdef USE_MY_MALLOC			/* metaconfig symbol */
#define XMALLOC_IS_MALLOC		/* xmalloc() becomes malloc() */
#endif

/*
 * The VMM layer is based on mmap() and falls back to posix_memalign()
 * or memalign().
 *
 * However, when trapping malloc() we also have to define posix_memalign(),
 * memalign() and valign() because glib 2.x can use these routines in its
 * slice allocator and the pointers returned by these functions must be
 * free()able.
 *
 * It follows that when mmap() is not available, we cannot trap malloc().
 *
 * On Windows, we do not have mmap() but we know we can trap malloc() hence
 * we allow the supersededing nonetheless.
 *
 */
#if defined(XMALLOC_IS_MALLOC) && !defined(HAS_MMAP) && !defined(MINGW32)
#undef XMALLOC_IS_MALLOC
#endif

#ifdef TRACK_MALLOC
#undef XMALLOC_IS_MALLOC
#endif

/**
 * Memory alignment constraints.
 *
 * Glib-2.30.2 does masking on pointer values with 0x7, relying on the
 * assumption that the system's malloc() will return pointers aligned on
 * 8 bytes.
 *
 * Apparently starting early 2020, the system malloc() was configured to
 * on MAX(2 * sizeof(size_t), __alignof__(long double)).
 *
 * We do not want to change the value of the MEM_ALIGNBYTES, which is also
 * used by other memory allocators, internal to gtk-gnutella, such as zalloc()
 * or omalloc(), where we know we will not make use of the "long double" type.
 *
 * To be able to work successfully on systems with such a glib, we have no
 * other option but to remain speachless... and comply with that assumption
 * for xmalloc(), in case it is going to be used to supersede the system malloc().
 * However we cannot use sizeof(size_t) in cpp tests, hence we use PTRSIZE
 * instead, which should be a good-enough substitute.
 *
 * Finally, this internal definition is now made in the "xmalloc.h" header and
 * not internally in xmalloc.c to be able to share the value with "hashing.h",
 * in particular, since we need to be careful about hashing pointers due to
 * the systematic presence of zeroes in the lower bits, thanks to alignment.
 * 		--RAM, 2020-06-19
 */
#ifdef XMALLOC_IS_MALLOC
/* Forced to comply with glib */
#define XMALLOC_ALIGNBYTES	MAX(2 * PTRSIZE, MEM_ALIGNBYTES)
#else
/* Internal use only */
#define XMALLOC_ALIGNBYTES	MEM_ALIGNBYTES
#endif	/* USE_MY_MALLOC */

/**
 * The largest block size in the free list represents the maximum block length
 * we agree to fragment.  Blocks larger than that are allocated via the VMM
 * layer and are therefore multiples of the system's page size.
 */
#define XMALLOC_MAXSIZE			32768	/**< Largest block size in free list */

/*
 * Flags for xmalloc_freelist_check()
 */

#define XMALLOC_FLCF_STATUS		(1U << 0)	/**< Log freelist status (OK/BAD) */
#define XMALLOC_FLCF_VERBOSE	(1U << 1)	/**< Log inconsitencies */
#define XMALLOC_FLCF_LOCK		(1U << 2)	/**< Lock buckets before checking */
#define XMALLOC_FLCF_UNLOCKED	(1U << 3)	/**< Check unlocked buckets */
#define XMALLOC_FLCF_LOGLOCK	(1U << 4)	/**< Log skipped locked buckets */

/*
 * Used by the thread management layer only.
 */

#ifdef THREAD_SOURCE
void xmalloc_thread_starting(unsigned stid);
void xmalloc_thread_ended(unsigned stid);
void xmalloc_thread_disable_local_pool(unsigned stid, bool disable);
#endif

/*
 * The "liberty" library defines and exports xmalloc(), xcalloc(), xrealloc()
 * and xfree() and causes link problems on ArchLinux, and maybe elsewhere
 * one day...  Remap them to "internal" names so that we do not have to change
 * the existing code.
 *		--RAM, 2016-10-28
 *
 * Likewise for xstrdup() (and probably xstrndup()) which is called by the BFD
 * library, and would cause free() errors when not compiled with xmalloc()
 * really being malloc(): our xstrdup() routine would be called, but the BFD
 * library probably expects to be able to free() such pointers!
 * 		--RAM, 2020-01-12
 */

#define xmalloc 	e_xmalloc
#define xcalloc		e_xcalloc
#define xrealloc	e_xrealloc
#define xfree		e_xfree

#define xstrdup		e_xstrdup
#define xstrndup	e_xstrndup

/*
 * Public interface.
 */

struct logagent;
struct sha1;

void set_xmalloc_debug(uint32 level);
bool xmalloc_thread_set_local_pool(bool on);
bool xmalloc_thread_uses_local_pool(unsigned stid);
void xmalloc_crash_mode(void);
void xmalloc_vmm_inited(void);
void xmalloc_pre_close(void);
void xmalloc_post_init(void);
bool xmalloc_is_malloc(void) G_CONST;
void xmalloc_show_settings(void);
void xmalloc_show_settings_log(struct logagent *la);
void xmalloc_stop_freeing(void);
void xmalloc_dump_stats(void);
void xmalloc_dump_stats_log(struct logagent *la, unsigned options);
void xmalloc_dump_usage_log(struct logagent *la, unsigned options);
void xmalloc_dump_freelist_log(struct logagent *la);
size_t xmalloc_freelist_check(struct logagent *la, unsigned flags);

void xmalloc_stats_digest(struct sha1 *digest);

void xgc(void);
void xmalloc_long_term(void);

void *xmalloc(size_t size) G_MALLOC G_NON_NULL;
void *xmalloc0(size_t size) G_MALLOC G_NON_NULL;
void *xhmalloc(size_t size) G_MALLOC G_NON_NULL;
void *xpmalloc(size_t size) G_MALLOC G_NON_NULL;
void *xcalloc(size_t nmemb, size_t size) G_MALLOC G_NON_NULL;
void *xrealloc(void *ptr, size_t size) WARN_UNUSED_RESULT G_NON_NULL;
void *xprealloc(void *ptr, size_t size) WARN_UNUSED_RESULT G_NON_NULL;
void xfree(void *ptr);
char *xstrdup(const char *str);
char *xstrndup(const char *str, size_t n);
void xstrfreev(char **str);
size_t xallocated(const void *p);
size_t xpallocated(const void *p);

bool xmalloc_block_info(const void *p, uint *tid, size_t *len);

#ifndef TRACK_MALLOC
static inline void * G_MALLOC G_NON_NULL
xcopy(const void *p, size_t size)
{
	void *cp = xmalloc(size);
	memcpy(cp, p, size);
	return cp;
}
#endif	/* !TRACK_MALLOC */

#define XCOPY(p)	xcopy(p, sizeof *p)

#define XMALLOC(p)			\
G_STMT_START {				\
	p = xmalloc(sizeof *p);	\
} G_STMT_END

#define XMALLOC0(p)				\
G_STMT_START {					\
	p = xmalloc0(sizeof *p);	\
} G_STMT_END

#define XFREE_NULL(p)	\
G_STMT_START {			\
	if (p) {			\
		xfree(p);		\
		p = NULL;		\
	}					\
} G_STMT_END

#define XMALLOC_ARRAY(p,n)			\
G_STMT_START {						\
	p = xmalloc((n) * sizeof p[0]);	\
} G_STMT_END

#define XMALLOC0_ARRAY(p,n)				\
G_STMT_START {							\
	p = xmalloc0((n) * sizeof p[0]);	\
} G_STMT_END

#define XREALLOC_ARRAY(p,n)				\
G_STMT_START {							\
	p = xrealloc(p, (n) * sizeof p[0]);	\
} G_STMT_END

#endif /* _xmalloc_h_ */

/* vi: set ts=4 sw=4 cindent:  */
