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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

void oob_init(void);
void oob_shutdown(void);
void oob_close(void);

void oob_got_results(struct gnutella_node *n, GSList *files,
		int count, host_addr_t addr, uint16 port,
		bool secure_oob, bool reliable_udp, unsigned flags);
void oob_deliver_hits(struct gnutella_node *n, const struct guid *muid,
		uint8 wanted, const struct array *token);

#endif /* _core_oob_h_ */

/* vi: set ts=4: */
