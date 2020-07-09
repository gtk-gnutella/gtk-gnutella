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
 * Well Equidistributed Long-period Linear (WELL) random number generator.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _well_h_
#define _well_h_

struct well_state;
typedef struct well_state well_state_t;

/*
 * Public interface.
 */

well_state_t *well_state_new(random_fn_t rf);
well_state_t *well_state_clone(const well_state_t *ws);
void well_state_free_null(well_state_t **ws_ptr);

uint32 well_state_rand(well_state_t *ws);
uint64 well_state_rand64(well_state_t *ws);
void well_state_addrandom(well_state_t *ws, const void *data, size_t len);

uint32 well_state_lock_rand(well_state_t *ws);
uint64 well_state_lock_rand64(well_state_t *ws);
void well_state_lock_addrandom(well_state_t *ws, const void *data, size_t len);

uint32 well_rand(void);
uint64 well_rand64(void);
void well_addrandom(const void *data, size_t len);

uint32 well_thread_rand(void);
uint64 well_thread_rand64(void);
void well_thread_addrandom(const void *data, size_t len);

struct pslist *well_users(void);

#endif /* _well_h_ */

/* vi: set ts=4 sw=4 cindent: */
