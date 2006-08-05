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
 * Handling of the (name, size) tuples.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"			/* For safe compilation under USE_DMALLOC */

RCSID("$Id$")

#include "namesize.h"

#include "lib/atoms.h"
#include "lib/walloc.h"
#include "lib/override.h"	/* Must be the last header included */

/**
 * Hash a `namesize_t' key.
 */
guint
namesize_hash(gconstpointer key)
{
	const namesize_t *k = (const namesize_t *) key;
	guint32 hash;

	hash = g_str_hash(k->name);
	hash ^= k->size;

	return hash;
}

/**
 * Compare two `namesize_t' keys.
 */
gint
namesize_eq(gconstpointer a, gconstpointer b)
{
	const namesize_t *ka = a;
	const namesize_t *kb = b;

	return ka->size == kb->size && 0 == strcmp(ka->name, kb->name);
}

/**
 * Create a new namesize structure.
 */
namesize_t *
namesize_make(const gchar *name, filesize_t size)
{
	namesize_t *ns;

	ns = walloc(sizeof(*ns));
	ns->name = atom_str_get(name);
	ns->size = size;

	return ns;
}

/**
 * Free a namesize structure.
 */
void
namesize_free(namesize_t *ns)
{
	atom_str_free(ns->name);
	wfree(ns, sizeof(*ns));
}

