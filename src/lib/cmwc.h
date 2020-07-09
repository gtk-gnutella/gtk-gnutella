/*
 * Copyright (c) 2014 Raphael Manfredi
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
 * Complimentary Multiply With Carry (CMWC) pseudo random number generator.
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#ifndef _cmwc_h_
#define _cmwc_h_

struct cmwc_state;
typedef struct cmwc_state cmwc_state_t;

/*
 * Public interface.
 */

cmwc_state_t *cmwc_state_new(random_fn_t rf);
cmwc_state_t *cmwc_state_clone(const cmwc_state_t *cs);
void cmwc_state_free_null(cmwc_state_t **cs_ptr);

uint32 cmwc_state_rand(cmwc_state_t *cs);
uint64 cmwc_state_rand64(cmwc_state_t *cs);
void cmwc_state_addrandom(cmwc_state_t *cs, const void *data, size_t len);

uint32 cmwc_state_lock_rand(cmwc_state_t *cs);
uint64 cmwc_state_lock_rand64(cmwc_state_t *cs);
void cmwc_state_lock_addrandom(cmwc_state_t *cs, const void *data, size_t len);

uint32 cmwc_rand(void);
uint64 cmwc_rand64(void);
void cmwc_addrandom(const void *data, size_t len);

uint32 cmwc_thread_rand(void);
uint64 cmwc_thread_rand64(void);
void cmwc_thread_addrandom(const void *data, size_t len);

struct pslist *cmwc_users(void);

#endif /* _cmwc_h_ */

/* vi: set ts=4 sw=4 cindent: */
