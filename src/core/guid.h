/*
 * $Id$
 *
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
 * Globally Unique ID (GUID) manager.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_guid_h_
#define _core_guid_h_

#include "common.h"

#include "if/core/guid.h"
#include "lib/host_addr.h"

/*
 * Public interface.
 */

void guid_init(void);
gboolean guid_is_gtkg(const struct guid *xuid,
	guint8 *majp, guint8 *minp, gboolean *relp);
gboolean guid_is_requery(const struct guid *xuid);
void guid_random_muid(struct guid *muid);
void guid_ping_muid(struct guid *muid);
void guid_query_muid(struct guid *muid, gboolean initial);
gboolean guid_query_muid_is_gtkg(const struct guid *guid,
	gboolean oob, guint8 *majp, guint8 *minp, gboolean *relp);
void guid_query_oob_muid(struct guid *muid,
	const host_addr_t addr, guint16 port, gboolean initial);
void guid_oob_get_addr_port(const struct guid *guid,
	host_addr_t *addr, guint16 *port);

#endif /* _core_guid_h_ */
