/*
 * Copyright (c) 2002-2003, 2014 Raphael Manfredi
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
 * Alive status checking ping/pongs.
 *
 * @author Raphael Manfredi
 * @date 2002-2003, 2014
 */

#ifndef _core_alive_h_
#define _core_alive_h_

#include "common.h"

#include "lib/timestamp.h"		/* For time_delta_t */

struct gnutella_node;
struct guid;

struct alive;
typedef struct alive alive_t;

/*
 * Public interface.
 */

alive_t *alive_make(struct gnutella_node *n, int max);
void alive_free(alive_t *a);
bool alive_send_ping(alive_t *a);
bool alive_ack_ping(alive_t *a, const struct guid *);
void alive_ack_first(alive_t *a, const struct guid *);
void alive_get_roundtrip_ms(const alive_t *a, uint32 *avg, uint32 *last);
time_delta_t alive_elapsed(const alive_t *a);

#endif /* _core_alive_h_ */

