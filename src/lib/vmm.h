/*
 * $Id$
 *
 * Copyright (c) 2006, Christian Biere
 * Copyright (c) 2006, 2009 Raphael Manfredi
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
 * Virtual memory management.
 *
 * @author Christian Biere
 * @date 2006
 * @author Raphael Manfredi
 * @date 2006, 2009
 */

#ifndef _vmm_h_
#define _vmm_h_

#include "common.h"

size_t round_pagesize(size_t n);
size_t compat_pagesize(void);
void *vmm_alloc(size_t size) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void *vmm_alloc0(size_t size) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void vmm_free(void *p, size_t size);
const char *prot_strdup(const char *s);
const void *vmm_trap_page(void);
gboolean vmm_is_fragment(const void *base, size_t size);

void set_vmm_debug(guint32 level);
void vmm_init(const void *sp);
void vmm_malloc_inited(void);
void vmm_post_init(void);

void vmm_madvise_free(void *p, size_t size);
void vmm_madvise_normal(void *p, size_t size);
void vmm_madvise_sequential(void *p, size_t size);
void vmm_madvise_willneed(void *p, size_t size);

void *vmm_mmap(void *addr, size_t length,
	int prot, int flags, int fd, off_t offset);
int vmm_munmap(void *addr, size_t length);

#define VMM_FREE_NULL(p, size) \
G_STMT_START { \
	if (p) { \
		vmm_free((p), (size)); \
		p = NULL; \
	} \
} G_STMT_END

#endif /* _vmm_h_ */

/* vi: set ts=4 sw=4 cindent: */
