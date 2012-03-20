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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

/**
 * Public interface.
 */

struct logagent;

void set_xmalloc_debug(uint32 level);
void xmalloc_crash_mode(void);
void xmalloc_vmm_inited(void);
void xmalloc_pre_close(void);
void xmalloc_post_init(void);
bool xmalloc_is_malloc(void) G_GNUC_CONST;
void xmalloc_show_settings(void);
void xmalloc_show_settings_log(struct logagent *la);
void xmalloc_stop_freeing(void);
void xmalloc_stop_wfree(void);
void xmalloc_dump_stats(void);
void xmalloc_dump_stats_log(struct logagent *la, unsigned options);
void xmalloc_dump_usage_log(struct logagent *la, unsigned options);
void xmalloc_dump_freelist_log(struct logagent *la);
size_t xmalloc_freelist_check(struct logagent *la, bool verbose);

void xgc(void);

void *xmalloc(size_t size) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void *xmalloc0(size_t size) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void *xpmalloc(size_t size) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void *xpmalloc0(size_t size) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void *xhmalloc(size_t size) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void *xcalloc(size_t nmemb, size_t size) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void *xrealloc(void *ptr, size_t size) WARN_UNUSED_RESULT;
void *xprealloc(void *ptr, size_t size) WARN_UNUSED_RESULT;
void xfree(void *ptr);
char *xstrdup(const char *str) WARN_UNUSED_RESULT G_GNUC_MALLOC;
char *xpstrdup(const char *str) WARN_UNUSED_RESULT G_GNUC_MALLOC;
char *xstrndup(const char *str, size_t n) WARN_UNUSED_RESULT G_GNUC_MALLOC;
char *xpstrndup(const char *str, size_t n) WARN_UNUSED_RESULT G_GNUC_MALLOC;

static inline void * WARN_UNUSED_RESULT G_GNUC_MALLOC
xcopy(const void *p, size_t size)
{
	void *cp = xmalloc(size);
	memcpy(cp, p, size);
	return cp;
}

static inline void * WARN_UNUSED_RESULT G_GNUC_MALLOC
xpcopy(const void *p, size_t size)
{
	void *cp = xpmalloc(size);
	memcpy(cp, p, size);
	return cp;
}

#define XFREE_NULL(p)	\
G_STMT_START {			\
	if (p) {			\
		xfree(p);		\
		p = NULL;		\
	}					\
} G_STMT_END

#endif /* _xmalloc_h_ */

/* vi: set ts=4 sw=4 cindent:  */
