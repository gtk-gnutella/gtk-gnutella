/*
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

#ifndef _gnet_net_stats_h_
#define _gnet_net_stats_h_

#include "common.h"
#include "ui_core_interface_gnet_stats_defs.h"

/***
 *** General statistics
 ***/

void gnet_stats_get(gnet_stats_t *stats);
void gnet_stats_udp_get(gnet_stats_t *stats);
void gnet_get_bw_stats(gnet_bw_source type, gnet_bw_stats_t *stats);

#endif /* _gnet_net_stats_h_ */
