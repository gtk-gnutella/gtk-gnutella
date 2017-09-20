/*
 * Copyright (c) 2002-2003, 2011, Raphael Manfredi
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
 * @date 2002-2003, 2011
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
void guid_close(void);

bool guid_is_banned(const guid_t *guid);
void guid_add_banned(const guid_t *guid);

bool guid_is_gtkg(const guid_t *xuid,
	uint8 *majp, uint8 *minp, bool *relp);
bool guid_is_requery(const guid_t *xuid);
void guid_random_muid(guid_t *muid);
void guid_ping_muid(guid_t *muid);
void guid_query_muid(guid_t *muid, bool initial);
bool guid_query_muid_is_gtkg(const guid_t *guid,
	bool oob, uint8 *majp, uint8 *minp, bool *relp);
void guid_query_oob_muid(guid_t *muid,
	const host_addr_t addr, uint16 port, bool initial);
void guid_oob_get_addr_port(const guid_t *guid,
	host_addr_t *addr, uint16 *port);

struct hikset;
const guid_t *guid_unique_atom(const struct hikset *hik, bool gtkg);

void guid_free_atom2(void *guid, void *unused);

#endif /* _core_guid_h_ */

/* vi: set ts=4 sw=4 cindent: */
