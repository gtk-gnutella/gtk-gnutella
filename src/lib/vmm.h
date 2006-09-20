/*
 * $Id$
 *
 * Copyright (c) 2006, Christian Biere
 * Copyright (c) 2006, Raphael Manfredi
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
 * @author Raphael Manfredi
 * @author Christian Biere
 * @date 2006
 */

#ifndef _vmm_h_
#define _vmm_h_

#include "common.h"

size_t round_pagesize(size_t n);
size_t compat_pagesize(void);
gpointer alloc_pages(size_t size);
void free_pages(gpointer p, size_t size);
size_t prune_page_cache(void);

#define FREE_PAGES_NULL(p, size) \
G_STMT_START { \
	if (p) { \
		free_pages((p), (size)); \
		p = NULL; \
	} \
} G_STMT_END

#endif /* _vmm_h_ */

/* vi: set ts=4 sw=4 cindent: */
