/*
 * $Id$
 *
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

/**
 * @ingroup core
 * @file
 *
 * Pong caching (LimeWire's ping/pong reducing scheme).
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#ifndef _core_inet_h_
#define _core_inet_h_

#include "common.h"
#include "lib/host_addr.h"

/*
 * Public interface.
 */

void inet_init(void);
void inet_close(void);

void inet_firewalled(void);
void inet_udp_firewalled(void);

gboolean inet_can_answer_ping(void);

void inet_got_incoming(const host_addr_t addr);
void inet_read_activity(void);
void inet_udp_got_incoming(const host_addr_t addr);
void inet_udp_record_sent(const host_addr_t addr);
void inet_udp_got_unsolicited_incoming(void);

void inet_connection_attempted(const host_addr_t addr);
void inet_connection_succeeded(const host_addr_t addr);

#endif /* _core_inet_h_ */

