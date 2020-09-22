/*
 * Copyright (c) 2012, Raphael Manfredi
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
 * Memory checking routines.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _mem_h_
#define _mem_h_

/**
 * Memory protections we know how to probe for.
 */
#define MEM_PROT_NONE		0
#define MEM_PROT_READ		(1U << 0)
#define MEM_PROT_WRITE		(1U << 1)
#define MEM_PROT_RW			(MEM_PROT_READ | MEM_PROT_WRITE)

/*
 * Public interface.
 */

int mem_protection(const void *p);

bool mem_is_valid_ptr(const void *p);
bool mem_is_valid_range(const void *p, size_t len);

bool mem_is_writable(const void *p);
bool mem_is_writable_range(const void *p, size_t len);

void mem_test(void);
bool mem_validity_testable(void);
bool mem_protection_testable(void);

/*
 * Convenience aliases, for symetry with mem_is_writable().
 */

static inline bool
mem_is_readable(const void *p)
{
	return mem_is_valid_ptr(p);
}

static inline bool
mem_is_readable_range(const void *p, size_t len)
{
	return mem_is_valid_range(p, len);
}

#endif /* _mem_h_ */

/* vi: set ts=4 sw=4 cindent: */
