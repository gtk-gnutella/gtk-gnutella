/*
 * Copyright (c) 2010 Raphael Manfredi
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
 * Memory allocator for objects that are never resized nor freed.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#ifndef _omalloc_h_
#define _omalloc_h_

void *omalloc(size_t size) G_MALLOC;
void *omalloc0(size_t size) G_MALLOC;
char *ostrdup(const char *str) G_MALLOC;
char *ostrndup(const char *str, size_t n) G_MALLOC;
const char *ostrdup_readonly(const char *str) G_MALLOC;
const void *ocopy_readonly(const void *p, size_t size) G_MALLOC;
const char *ostrndup_readonly(const char *str, size_t n) G_MALLOC;

static inline void * G_MALLOC
ocopy(const void *p, size_t size)
{
	void *cp = omalloc(size);
	memcpy(cp, p, size);
	return cp;
}

#define OCOPY(p)	ocopy(p, sizeof *p)

struct logagent;

size_t omalloc_page_count(void);
void set_omalloc_debug(uint32 level);
void omalloc_close(void);
void omalloc_dump_stats_log(struct logagent *la, unsigned options);

#define OMALLOC(p)			\
G_STMT_START {				\
	p = omalloc(sizeof *p);	\
} G_STMT_END

#define OMALLOC0(p)				\
G_STMT_START {					\
	p = omalloc0(sizeof *p);	\
} G_STMT_END

#define OMALLOC_ARRAY(p,n)			\
G_STMT_START {						\
	p = omalloc((n) * sizeof p[0]);	\
} G_STMT_END

#define OMALLOC0_ARRAY(p,n)				\
G_STMT_START {							\
	p = omalloc0((n) * sizeof p[0]);	\
} G_STMT_END

#endif /* _omalloc_h_ */

/* vi: set ts=4 sw=4 cindent:  */
