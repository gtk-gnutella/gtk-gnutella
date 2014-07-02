/*
 * Copyright (c) 2001-2003, Raphael Manfredi
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

#ifndef _core_hosts_h_
#define _core_hosts_h_

#include "common.h"

#include "lib/host_addr.h"

/*
 * Global Data
 */

extern bool host_low_on_pongs;

/*
 * Global Functions
 */

void host_init(void);
void host_timer(void);
void host_add(const host_addr_t addr, uint16, bool);
void host_add_semi_pong(const host_addr_t addr, uint16 port);
void host_shutdown(void);
void host_close(void);

void parse_netmasks(const char *value);
bool host_is_nearby(const host_addr_t addr);
bool host_is_valid(const host_addr_t addr, uint16 port);
bool host_address_is_usable(const host_addr_t addr);

#endif /* _core_hosts_h_ */

/* vi: set ts=4 sw=4 cindent: */
