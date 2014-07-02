/*
 * Copyright (c) 2001 Geoff Kuenning
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Mersenne Twister Pseudo Random Number Generator.
 *
 * This is a stripped-down implementation originating from the LGPL version
 * from Geoff Kuenning, released March 18, 2001.
 *
 * Original source code was obtained at:
 * http://www.cs.hmc.edu/~geoff/tars/mtwist-1.1.tgz
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _mtwist_h_
#define _mtwist_h_

struct mt_state;
typedef struct mt_state mt_state_t;

void mt_init(void);

mt_state_t *mt_state_new(random_fn_t rf);
mt_state_t *mt_state_clone(const mt_state_t *mts);
void mt_state_free_null(mt_state_t **mts_ptr);

uint32 mts_rand(register mt_state_t *mts);
uint64 mts_rand64(register mt_state_t *mts);

uint32 mts_lock_rand(register mt_state_t *mts);
uint64 mts_lock_rand64(register mt_state_t *mts);

uint32 mt_rand(void);
uint64 mt_rand64(void);

uint32 mt_thread_rand(void);
uint64 mt_thread_rand64(void);

#endif /* _mtwist_h_ */

/* vi: set ts=4 sw=4 cindent: */
