/*
 * Copyright (c) 2012 Raphael Manfredi
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
 * Default mempcpy() implementation.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include "mempcpy.h"

#ifndef HAS_MEMPCPY
/**
 * A memcpy() routine returning the first destination byte beyond the copy.
 */
void *
mempcpy(void *dest, const void *src, size_t n)
{
	memcpy(dest, src, n);
	return ptr_add_offset(dest, n);
}
#endif	/* !HAS_MEMPCPY */

/* vi: set ts=4 sw=4 cindent: */
