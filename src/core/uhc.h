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
 * UDP Host Cache.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#ifndef _core_uhc_h_
#define _core_uhc_h_

#include "common.h"

#include "lib/host_addr.h"

/*
 * Public interface.
 */

struct gnutella_node;

void uhc_init(void);
void uhc_close(void);

void uhc_get_hosts(void);
bool uhc_is_waiting(void);

void uhc_ipp_extract(
	struct gnutella_node *n, const char *payload, int paylen, enum net_type nt);

#endif /* _core_uhc_h_ */

/* vi: set ts=4 sw=4 cindent: */
