/*
 * $Id$
 *
 * Copyright (c) 2006, Raphael Manfredi
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
 * @ingroup dht
 * @file
 *
 * Kademlia Unique ID (KUID) manager.
 *
 * @author Raphael Manfredi
 * @date 2006
 */

#ifndef _dht_routing_h_
#define _dht_routing_h_

#define K_BUCKET_PUBLIC		20		/* Supposed to keep only 20 per bucket */
#define K_BUCKET_GOOD		30		/* Really keep 30 contacts per bucket */
#define K_BUCKET_STALE		20		/* Keep 20 possibly "stale" contacts */
#define K_BUCKET_PENDING	10		/* Keep 10 pending contacts */

/*
 * Public interface.
 */

void dht_route_init(void);
void dht_route_close(void);

#endif /* _dht_routing_h_ */

