/*
 * Copyright (c) 2003, Raphael Manfredi
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
 * @ingroup core
 * @file
 *
 * Maintain an accurate clock skew of our host's clock with respect
 * to the absolute time.
 *
 * @author Raphael Manfredi
 * @date 2003
 */

#ifndef _core_clock_h_
#define _core_clock_h_

#include "common.h"
#include "lib/host_addr.h"

/*
 * Public interface.
 */

void clock_init(void);
void clock_close(void);

void clock_update(time_t update, int precision, const host_addr_t addr);

time_t clock_loc2gmt(time_t stamp);
time_t clock_gmt2loc(time_t stamp);

#endif /* _core_clock_h_ */

/* vi: set ts=4 sw=4 cindent: */
