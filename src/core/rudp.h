/*
 * Copyright (c) 2006, Christian Biere
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
 * "Reliable" UDP connections.
 *
 * @author Christian Biere
 */

#ifndef _core_rudp_h_
#define _core_rudp_h_

#include "common.h"

struct rudp_con;

int rudp_connect(const host_addr_t addr, uint16 port);
void rudp_handle_packet(const host_addr_t addr, uint16 port,
	const void *data, size_t size);
ssize_t rudp_write(struct rudp_con *con, const void *data, size_t size);
ssize_t rudp_read(struct rudp_con *con, void *data, size_t size);
int rudp_close(struct rudp_con *con);

host_addr_t rudp_get_addr(const struct rudp_con *con);
uint16 rudp_get_port(const struct rudp_con *con);

void rudp_set_event_handler(struct rudp_con *con,
		inputevt_cond_t cond, inputevt_handler_t handler, void *data);
void rudp_clear_event_handler(struct rudp_con *con);

void rudp_timer(time_t now);
void rudp_init(void);

#endif /* _core_rudp_h_ */

/* vi: set ts=4 sw=4 cindent: */
