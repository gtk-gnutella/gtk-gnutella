/*
 * Copyright (c) 2003, Christian Biere
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
 * Asynchronous DNS lookup.
 *
 * @author Christian Biere
 * @date 2003
 */

#ifndef _adns_h_
#define _adns_h_

#include "common.h"
#include "host_addr.h"	/* For ``struct host_addr'' */

typedef void (*adns_callback_t)(const host_addr_t *, size_t, void *);
typedef void (*adns_reverse_callback_t)(const char *, void *);

void adns_init(void);
bool adns_resolve(const char *, enum net_type net,
	adns_callback_t, void *);
bool adns_reverse_lookup(const host_addr_t,
	adns_reverse_callback_t, void *);
void adns_close(void);

#endif /* _adns_h_ */

/* vi: set ts=4 sw=4 cindent: */
