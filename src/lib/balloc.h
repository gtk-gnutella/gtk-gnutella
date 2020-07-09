/*
 * Copyright (c) 2016 Raphael Manfredi
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
 * Buffer-based allocator.
 *
 * @author Raphael Manfredi
 * @date 2016
 */

#ifndef _balloc_h_
#define _balloc_h_

/*
 * Public interface.
 */

void balloc_init(uint32 size, void *base, size_t length);
bool balloc_is_initialized(const void *base);

void *balloc_alloc(void *base) G_MALLOC;
void balloc_free(void *base, void *p);

#endif /* _balloc_h_ */

/* vi: set ts=4 sw=4 cindent: */
