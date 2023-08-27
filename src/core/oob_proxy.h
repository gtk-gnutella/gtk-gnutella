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
 * Proxied Out-of-band queries.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#ifndef _core_oob_proxy_h_
#define _core_oob_proxy_h_

#include "common.h"

/*
 * Public interface.
 */

struct array;
struct gnutella_node;
struct guid;

void oob_proxy_init(void);
void oob_proxy_close(void);

bool oob_proxy_create(struct gnutella_node *n);
bool oob_proxy_pending_results(
	struct gnutella_node *n, const struct guid *muid,
	int hits, bool udp_firewalled, const struct array *token);
bool oob_proxy_got_results(struct gnutella_node *n, uint results);
const struct guid *oob_proxy_muid_proxied(const struct guid *muid);

#endif /* _core_oob_proxy_h_ */

/* vi: set ts=4 sw=4 cindent: */
