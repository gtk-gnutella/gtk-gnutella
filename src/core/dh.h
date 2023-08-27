/*
 * Copyright (c) 2004, Raphael Manfredi
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
 * @ingroup core
 * @file
 *
 * Dynamic hits.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#ifndef _core_dh_h_
#define _core_dh_h_

#include "common.h"

/*
 * Public interface.
 */

struct gnutella_node;
struct guid;

void dh_init(void);
void dh_close(void);

void dh_got_results(const struct guid *muid, int count);
void dh_timer(time_t now);
void dh_route(
	struct gnutella_node *src, struct gnutella_node *dest, int count);
bool dh_would_route(const struct guid *m, struct gnutella_node *d, int cnt);

#endif	/* _core_dh_h_ */

/* vi: set ts=4 sw=4 cindent: */
