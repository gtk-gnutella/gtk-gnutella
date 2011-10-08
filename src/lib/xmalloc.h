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

void set_xmalloc_debug(guint32 level);
void xmalloc_vmm_inited(void);
void xmalloc_pre_close(void);
void xmalloc_post_init(void);
gboolean xmalloc_is_malloc(void) G_GNUC_CONST;
void xmalloc_stop_freeing(void);

void *xmalloc(size_t size) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void *xcalloc(size_t nmemb, size_t size) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void *xrealloc(void *ptr, size_t size) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void xfree(void *ptr);

#endif /* _xmalloc_h_ */

/* vi: set ts=4 sw=4 cindent:  */
