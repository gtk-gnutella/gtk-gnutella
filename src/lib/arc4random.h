/*
 * Copyright (c) 2010, 2013 Raphael Manfredi
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
 * ARC4 random number generator.
 *
 * @author Raphael Manfredi
 * @date 2010, 2013
 */

#ifndef _arc4random_h_
#define _arc4random_h_

#include "common.h"

#ifdef HAS_ARC4RANDOM
/*
 * Rename our implementation so that it does not conflict
 * with the one on this system.
 *
 * The arc4random routines not remapped here were not part of
 * the initial ARC4 interface and are therefore left untouched.
 *
 *		--RAM, 2020-06-23
 */
#define arc4random				xrc4random
#define arc4random_stir			xrc4random_stir
#define arc4random_addrandom	xrc4random_addrandom
#endif	/* HAS_ARC4RANDOM */

/*
 * Public interface.
 */

uint32 arc4random(void);
void arc4random_stir(void);
void arc4random_addrandom(const unsigned char *dat, int datlen);

void arc4random_stir_once(void);
uint64 arc4random64(void);

/*
 * ARC4 random numbers using thread-local stream.
 */

uint32 arc4_thread_rand(void);
uint64 arc4_thread_rand64(void);
void arc4_thread_addrandom(const unsigned char *dat, int datlen);
struct pslist *arc4_users(void);

#endif /* _arc4random_h_ */

/* vi: set ts=4 sw=4 cindent: */
