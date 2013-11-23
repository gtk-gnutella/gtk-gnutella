/*
 * Copyright (c) 2013 Raphael Manfredi
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
 * Thread Magazine allocator.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _tmalloc_h_
#define _tmalloc_h_

typedef struct tmalloc_depot tmalloc_t;

void set_tmalloc_debug(uint32 level);

tmalloc_t *tmalloc_create(const char *name, size_t size,
	alloc_fn_t allocate, free_size_fn_t deallocate);
void tmalloc_reset(tmalloc_t *tma);
size_t tmalloc_size(const tmalloc_t *tma);

void *tmalloc(tmalloc_t *tma) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void *tmalloc0(tmalloc_t *tma) WARN_UNUSED_RESULT G_GNUC_MALLOC;
void tmfree(tmalloc_t *tma, void *p);

#endif /* _tmalloc_h_ */

/* vi: set ts=4 sw=4 cindent: */
