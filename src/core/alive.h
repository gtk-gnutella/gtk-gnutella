/*
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * @date 2002-2003
 */

#ifndef _core_alive_h_
#define _core_alive_h_

#include "common.h"

struct gnutella_node;
struct guid;

/*
 * Public interface.
 */

void *alive_make(struct gnutella_node *n, int max);
void alive_free(void *obj);
bool alive_send_ping(void *obj);
bool alive_ack_ping(void *obj, const struct guid *);
void alive_ack_first(void *obj, const struct guid *);
void alive_get_roundtrip_ms(const void *obj, uint32 *avg, uint32 *last);

#endif /* _core_alive_h_ */

