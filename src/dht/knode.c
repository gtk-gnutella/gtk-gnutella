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
 * A Kademlia node.
 *
 * @author Raphael Manfredi
 * @date 2006
 */

#include "common.h"

RCSID("$Id$");

#include "knode.h"

#include "lib/atoms.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/**
 * Allocate new Kademlia node.
 */
knode_t *
knode_new(kuid_t *id, host_addr_t addr, guint16 port)
{
	knode_t *kn;

	kn = walloc0(sizeof *kn);
	kn->id = (kuid_t *) atom_sha1_get(id->v);
	kn->refcnt = 1;
	kn->addr = addr;
	kn->port = port;
	kn->status = KNODE_UNKNOWN;

	return kn;
}

/**
 * Reclaim memory used by Kademlia node.
 */
static void
knode_dispose(knode_t *kn)
{
	g_assert(kn->refcnt == 0);

	atom_sha1_free(kn->id->v);
	wfree(kn, sizeof *kn);
}

/**
 * Remove a reference on a Kademlia node, disposing of the structure when
 * none remain.
 */
void
knode_free(knode_t *kn)
{
	if (--kn->refcnt)
		return;

	knode_dispose(kn);
}

/* vi: set ts=4 sw=4 cindent: */
