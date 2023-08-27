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
 * Out-of-band query hit management.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#ifndef _core_oob_h_
#define _core_oob_h_

#include "common.h"

#include "lib/host_addr.h"

/*
 * Public interface.
 */

struct array;
struct gnutella_node;
struct guid;
struct pslist;

void oob_init(void);
void oob_shutdown(void);
void oob_close(void);

void oob_got_results(struct gnutella_node *n, struct pslist *files,
		int count, host_addr_t addr, uint16 port,
		bool secure_oob, bool reliable_udp, unsigned flags);
void oob_deliver_hits(struct gnutella_node *n, const struct guid *muid,
		uint8 wanted, const struct array *token);

#endif /* _core_oob_h_ */

/* vi: set ts=4 sw=4 cindent: */
