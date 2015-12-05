/*
 * Copyright (c) 2015 Raphael Manfredi
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
 * Virtual Memory Emergency Allocator (VMEA).
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#ifndef _vmea_h_
#define _vmea_h_

/*
 * Public interface.
 */

void vmea_reserve(size_t size, bool capture);
void vmea_close(void);

void *vmea_alloc(size_t size) WARN_UNUSED_RESULT G_GNUC_MALLOC;
bool vmea_free(void *p, size_t size);

size_t vmea_capacity(void);
size_t vmea_allocated(void);
size_t vmea_allocations(void);
size_t vmea_maxsize(void);

#endif /* _vmea_h_ */

/* vi: set ts=4 sw=4 cindent: */
