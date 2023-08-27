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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Alea Jacta Est (AJE) -- a pseudo RNG inspired by Fortuna and Yarrow.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _aje_h_
#define _aje_h_

/*
 * Public interface.
 */

uint32 aje_rand(void);
uint64 aje_rand64(void);
void aje_random_bytes(void *dest, size_t len);
void aje_addrandom(const void *src, size_t len);
uint32 aje_rand_strong(void);
uint64 aje_rand64_strong(void);

uint32 aje_thread_rand(void);
uint64 aje_thread_rand64(void);
void aje_thread_random_bytes(void *dest, size_t len);
void aje_thread_addrandom(const void *data, size_t len);
uint32 aje_thread_rand_strong(void);
uint64 aje_thread_rand64_strong(void);

struct pslist *aje_users(void);

#endif /* _aje_h_ */

/* vi: set ts=4 sw=4 cindent: */
